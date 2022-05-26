package github

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-github/github"
	"github.com/valyala/fastjson"
)

const apiDownloadBufSize = 16 * 1024 * 1024

func scanFile(jdata *fastjson.Value, matches *[]diffMatchInfo) error {
	patch := string(jdata.Get("patch").GetStringBytes())
	lineNum := -1

	scannerp := bufio.NewScanner(strings.NewReader(patch))
	for scannerp.Scan() {
		if err := scannerp.Err(); err != nil {
			return err
		}

		line := scannerp.Text()

		if line[0] == '+' {
			cinfo := findSecret(line)
			if cinfo != nil {
				var di diffMatchInfo
				di.Type = cinfo.secretType
				di.Desc = cinfo.desc
				di.Platform = cinfo.platform
				di.Line = uint64(lineNum) - 1

				*matches = append(*matches, di)
			}
		} else if len(line) >= 2 && line[0:2] == "@@" {
			// Example of line format:
			//  @@ -17,3 +17,10 @@ assumed_role = False @@
			// We need to parse the '+17,10' part to extract the start line we're tied to
			ls := strings.Split(line, " ")
			if len(ls) < 3 {
				return fmt.Errorf("cannot understand diff line %s (1)", line)
			}
			al := ls[2]
			if len(al) < 4 || al[0] != '+' {
				return fmt.Errorf("cannot understand diff line %s (2)", line)
			}

			al = al[1:]
			linesStr := strings.Split(al, ",")
			addstart, err := strconv.Atoi(linesStr[0])
			if err != nil {
				return fmt.Errorf("cannot understand diff line %s (3)", line)
			}

			lineNum = addstart
		} else if line[0] == '-' {
			continue
		}

		if lineNum == -1 {
			return fmt.Errorf("missed unified diff header from file")
		}
		lineNum++
	}

	return nil
}

func scanDiff(oCtx *openContext, repo string, refs string, diffFiles *[]diffFileInfo) error {
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

	// Process all of the diffs in the reponse
	flist := jdata.GetArray("files")
	if flist == nil {
		return nil
	}

	for _, file := range flist {
		var fmi diffFileInfo
		fmi.FileName = string(file.Get("filename").GetStringBytes())

		err := scanFile(file, &fmi.Matches)
		if err != nil {
			return err
		}

		*diffFiles = append(*diffFiles, fmi)
	}

	return nil
}

func handleHook(w http.ResponseWriter, r *http.Request, oCtx *openContext) {
	payload, err := github.ValidatePayload(r, []byte(oCtx.whSecret))
	if err != nil {
		// oCtx.whSrvChan <- []byte("E " + err.Error())
		log.Printf("[%s] signature check failed, skipping message from %s.\n", PluginName, r.RemoteAddr)
		return
	}

	defer r.Body.Close()

	// GitHub's webook messages encode the webook type as an http header instead of
	// putting it in the json, which is very unfortunate becasue it forces us to
	// add it manually.
	// Currently, we do this by unmarshaling the string, adding an additional
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

func notifyError(oCtx *openContext, err error) {
	if oCtx.whSrv != nil {
		oCtx.whSrv.Shutdown(context.Background())
	}
	oCtx.whSrv = nil
	oCtx.whSrvChan <- []byte("E " + err.Error())
	return
}

func server(p *pluginContext, oCtx *openContext) {
	secretsDir := p.config.SecretsDir

	crtName := secretsDir + "/server.crt"
	keyName := secretsDir + "/server.key"

	oCtx.whSrv = nil

	isHttps := p.config.UseHTTPs

	if isHttps {
		if !(fileExists(crtName) && fileExists(keyName)) {
			err := fmt.Errorf("[%s] webhook webserver is configured to use HTTPs, but either %s or %s can't be found. Either provide the secrets, or set the UseHTTPs init parameter to false.\n", PluginName, keyName, crtName)
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
