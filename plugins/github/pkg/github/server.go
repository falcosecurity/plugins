// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package github

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/go-github/github"
	"github.com/valyala/fastjson"
)

const apiDownloadBufSize = 16 * 1024 * 1024

var (
	rgxHunkShort = regexp.MustCompile(`^@@ -(?:\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@.*`)
	rgxHunkLong  = regexp.MustCompile(`^@@@ -(?:\d+)(?:,\d+)? -(?:\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@@.*`)
	nullCommitID = "0000000000000000000000000000000000000000"
)

// scanning a git diff line by line, looking for line additions
// containing secrets or sensitive information
func scanDiffPatch(patch string, onAddition func(lineNum uint64, line string)) error {
	var err error
	var line string
	var match []string
	hunkLineNum := -1

	scan := bufio.NewScanner(strings.NewReader(patch))
	for scan.Scan() {
		line = scan.Text()
		if strings.HasPrefix(line, "+") {
			onAddition(uint64(hunkLineNum)-1, line[1:])
		} else if strings.HasPrefix(line, "-") {
			// ignore deletions
			continue
		} else if strings.HasPrefix(line, "@@") {
			match = rgxHunkShort.FindStringSubmatch(line)
			if len(match) != 2 {
				match = rgxHunkLong.FindStringSubmatch(line)
			}
			if len(match) == 2 {
				hunkLineNum, err = strconv.Atoi(match[1])
				if err != nil {
					return fmt.Errorf("cannot parse diff hunk line %s: %s", line, err.Error())
				}
			}
		}

		// note: this assumes that a hunk header is the first line of the diff
		// this would not work in generic git diffs, but it's what we want
		// for our API calls
		if hunkLineNum == -1 {
			return fmt.Errorf("missed unified diff header from file")
		}
		hunkLineNum++
	}

	return scan.Err()
}

func scanDiff(oCtx *PluginInstance, repo string, refs string, diffFiles *[]diffFileInfo) error {
	// Issue the compare request
	resp, err := oCtx.ghOauth.tc.Get("https://api.github.com/repos/" + repo + "/compare/" + refs)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	//fmt.Println("Response status:", resp.Status)
	if resp.StatusCode != 200 {
		return fmt.Errorf("unable to fetch data from the github API, status: %s", resp.Status)
	}

	jsonStr := ""
	scanner := bufio.NewScanner(resp.Body)

	// The request can fail if the diff is bigger than the scanner buffer.
	// Make sure there is ample space for it.
	buf := make([]byte, apiDownloadBufSize)
	scanner.Buffer(buf, apiDownloadBufSize)

	// Consume the whole response
	for scanner.Scan() {
		jsonStr += scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Parse the response as json
	var jparser fastjson.Parser
	jdata, err := jparser.Parse(jsonStr)
	if err != nil {
		return err
	}

	// Process all the diffs in the response
	flist := jdata.GetArray("files")
	if flist == nil {
		return nil
	}

	for _, file := range flist {
		fmi := diffFileInfo{
			FileName: string(file.Get("filename").GetStringBytes()),
		}
		err := scanDiffPatch(string(file.Get("patch").GetStringBytes()), func(n uint64, l string) {
			cinfo := findSecret(l)
			if cinfo != nil {
				fmi.Matches = append(fmi.Matches, diffMatchInfo{
					Type:     cinfo.secretType,
					Desc:     cinfo.desc,
					Platform: cinfo.platform,
					Line:     n,
				})
			}
		})
		if err != nil {
			return err
		}

		*diffFiles = append(*diffFiles, fmi)
	}

	return nil
}

func scanWorkFlowYaml(oCtx *PluginInstance, fileName string, repoName string, workflowInfo *workflowFileInfo) error {
	fileUrl := "https://api.github.com/repos/" + repoName + "/contents/" + fileName

	// Issue the compare request
	resp, err := oCtx.ghOauth.tc.Get(fileUrl)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("unable to fetch data from the github API, status: %s", resp.Status)
	}

	jsonStr := ""
	scanner := bufio.NewScanner(resp.Body)

	// The request can fail if the diff is bigger than the scanner buffer.
	// Make sure there is ample space for it.
	buf := make([]byte, apiDownloadBufSize)
	scanner.Buffer(buf, apiDownloadBufSize)

	// Consume the whole response
	for scanner.Scan() {
		jsonStr += scanner.Text()
	}
	if err := scanner.Err(); err != nil {
		return err
	}

	// Parse the response as json
	var jparser fastjson.Parser
	jdata, err := jparser.Parse(jsonStr)
	if err != nil {
		return err
	}

	workflowInfo.FileName = fileName

	contentB64 := string(jdata.GetStringBytes("content"))
	if contentB64 != "" {
		content, err := base64.StdEncoding.DecodeString(contentB64)
		if err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(content)))
			var ln uint64
			for scanner.Scan() {
				ln += 1
				minfo := findMiner(scanner.Text())
				if minfo != "" {
					workflowInfo.MinerMatches = append(workflowInfo.MinerMatches, minerDetectionInfo{
						Type: minfo,
						Line: ln,
					})
				}
			}
		}
	}

	return nil
}

func handleHook(w http.ResponseWriter, r *http.Request, oCtx *PluginInstance) {
	payload, err := github.ValidatePayload(r, []byte(oCtx.whSecret))
	if err != nil {
		// oCtx.whSrvChan <- []byte("E " + err.Error())
		log.Printf("[%s] signature check failed, skipping message from %s.\n", PluginName, r.RemoteAddr)
		return
	}

	defer r.Body.Close()

	// GitHub's webhook messages encode the webhook type as a http header instead of
	// putting it in the json, which is very unfortunate because it forces us to
	// add it manually.
	// Currently, we do this by unmarshalling the string, adding an additional
	// webhook_type property and then marshaling it.
	// This is clearly very inefficient, but for the moment we don't care, assuming
	// that the message frequency will always be low enough not to cause concerns.
	// If this becomes an issue, the code can be easily optimized.
	var jmap map[string]interface{}
	err = json.Unmarshal(payload, &jmap)
	if err != nil {
		// Not a json file, return an error.
		oCtx.whSrvChan <- []byte("E " + err.Error())
		return
	}

	whType := github.WebHookType(r)

	// For push events, we go fetch the diff (by doing another requesto to github) and inspect
	// it to look for secrets that the author might have committed.
	// If we find any committed secret, we add its information to a new section in the webhook
	// json, so that the extractors can have easy access to it.
	if whType == "push" {
		// If a branch is being created or deleted, a push event is sent before create or delete events.
		// So we extract the before and after commit IDs. If either is null, then it means that a branch
		// is being created or deleted.
		beforeCommitID := jmap["before"]
		afterCommitID := jmap["after"]
		if beforeCommitID != nullCommitID && afterCommitID != nullCommitID {
			// extract the diff parameters (refs and repo name) from the webhook json
			cmpIfc := jmap["compare"]
			if cmpIfc != nil {
				cmpStr := cmpIfc.(string)
				refsStart := strings.LastIndex(cmpStr, "/")
				if refsStart < 5 || len(cmpStr)-refsStart < 5 {
					oCtx.whSrvChan <- []byte("E malformed compare field in push json: " + cmpStr)
					return
				}
				refsStr := cmpStr[refsStart+1:]

				repoMap := jmap["repository"].(map[string]interface{})
				if repoMap != nil {
					repoFullNameIfc := repoMap["full_name"]
					if repoFullNameIfc != nil {
						repoFullName := repoFullNameIfc.(string)

						var diffFiles []diffFileInfo
						// Make the diff request and analyze it
						err := scanDiff(oCtx, repoFullName, refsStr, &diffFiles)
						if err != nil {
							oCtx.whSrvChan <- []byte("E " + err.Error())
							return
						}

						// Add the results to the webhook json
						jmap["files"] = diffFiles
					}
				}
			}
		}
	} else if whType == "workflow_run" {
		jrepo := jmap["repository"]
		if jrepo != nil {
			jreponame := jrepo.(map[string]interface{})["full_name"]
			if jreponame != nil {
				reponame := jreponame.(string)

				// extract the diff parameters (refs and repo name) from the webhook json
				wr := jmap["workflow"]
				if wr != nil {
					wurl := wr.(map[string]interface{})["path"]
					if wurl != nil {
						var winfo workflowFileInfo
						scanWorkFlowYaml(oCtx, wurl.(string), reponame, &winfo)

						// Add the results to the webhook json
						jmap["workflow_miner_detections"] = winfo
					}
				}
			}
		}
	}

	jmap["webhook_type"] = whType
	jsonString, err := json.Marshal(jmap)
	if err != nil {
		jsonString = []byte("E " + err.Error())
	}

	oCtx.whSrvChan <- jsonString
}

func fileExists(fname string) bool {
	_, err := os.Stat(fname)
	if err != nil && errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}

func notifyError(oCtx *PluginInstance, err error) {
	if oCtx.whSrv != nil {
		oCtx.whSrv.Shutdown(context.Background())
	}
	oCtx.whSrv = nil
	oCtx.whSrvChan <- []byte("E " + err.Error())
}

func server(p *Plugin, oCtx *PluginInstance) {
	secretsDir := p.config.SecretsDir

	crtName := secretsDir + "/server.crt"
	keyName := secretsDir + "/server.key"

	oCtx.whSrv = nil

	isHttps := p.config.UseHTTPs

	if isHttps {
		if !(fileExists(crtName) && fileExists(keyName)) {
			err := fmt.Errorf("[%s] webhook webserver is configured to use HTTPs, but either %s or %s can't be found. Either provide the secrets, or set the UseHTTPs init parameter to false", PluginName, keyName, crtName)
			notifyError(oCtx, err)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			handleHook(w, r, oCtx)
		},
	))

	oCtx.whSrv = &http.Server{
		Handler: mux,
	}

	var err error
	if isHttps {
		log.Printf("[%s] starting HTTPs webhook server on port 443\n", PluginName)
		err = oCtx.whSrv.ListenAndServeTLS(crtName, keyName)
	} else {
		log.Printf("[%s] starting HTTP webhook server on port 80\n", PluginName)
		err = oCtx.whSrv.ListenAndServe()
	}

	if err != nil {
		notifyError(oCtx, err)
		return
	}
}
