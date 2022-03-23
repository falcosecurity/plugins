/*
Copyright (C) 2022 The Falco Authors.

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

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"
)

const (
	webServerParamRgxStr         = "^(localhost)?(:[0-9]+)(\\/[.\\-\\w]+)$"
	webServerShutdownTimeoutSecs = 5
)

func (k *K8SAuditPlugin) Open(params string) (source.Instance, error) {
	if strings.HasPrefix(params, "file://") {
		return k.openLocalFile(params[len("file://"):])
	}

	ssl := false
	webServerParam := ""
	webServerParamRgx, err := regexp.Compile(webServerParamRgxStr)
	if err != nil {
		return nil, err
	}
	if strings.HasPrefix(params, "http://") {
		webServerParam = params[len("http://"):]
	} else if strings.HasPrefix(params, "https://") {
		webServerParam = params[len("https://"):]
		ssl = true
	} else {
		return nil, fmt.Errorf("invalid open parameters (supported prefixes are 'file://', 'http://', and 'https://'): %s", params)
	}
	matches := webServerParamRgx.FindStringSubmatch(webServerParam)
	if matches == nil || len(matches) != 4 {
		return nil, fmt.Errorf("webserver parameter does not match the regex '%s': %s", webServerParamRgxStr, webServerParam)
	}
	return k.openWebServer(matches[2], matches[3], ssl)
}

// Opens parameters with "file://" prefix, which represent one or more
// JSON objects encoded with JSONL notation in a file on the local filesystem.
// Each JSON object produces an event in the returned event source.
func (k *K8SAuditPlugin) openLocalFile(filePath string) (source.Instance, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	eventChan := make(chan []byte)
	errorChan := make(chan error)
	go func() {
		defer file.Close()
		defer close(eventChan)
		defer close(errorChan)
		scanner := bufio.NewScanner(file)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) > 0 {
				eventChan <- ([]byte)(line)
			}
		}
		if scanner.Err() != nil {
			errorChan <- err
		}
	}()
	return k8saudit.OpenEventSource(context.Background(), eventChan, errorChan, k.config.TimeoutMillis, nil)
}

// Opens parameters with "http://" and "https://" prefixes.
// Starts a webserver and listens for K8S Audit Event webhooks.
func (k *K8SAuditPlugin) openWebServer(port, endpoint string, ssl bool) (source.Instance, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	eventChan := make(chan []byte)
	errorChan := make(chan error)

	// configure server
	m := http.NewServeMux()
	s := &http.Server{Addr: port, Handler: m}
	m.HandleFunc(endpoint, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			http.Error(w, fmt.Sprintf("%s method not allowed", req.Method), http.StatusMethodNotAllowed)
			return
		}
		if req.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "wrong Content Type", http.StatusBadRequest)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, int64(k.config.MaxEventBytes))
		bytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			msg := fmt.Sprintf("bad request: %s", err.Error())
			// todo: use SDK Go native logging once available, see:
			// https://github.com/falcosecurity/plugin-sdk-go/issues/24
			println("ERROR: " + msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		eventChan <- bytes
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>Ok</body></html>"))
	})

	// launch server
	go func() {
		//defer close(eventChan)
		defer close(errorChan)
		var err error
		if ssl {
			// note: the legacy K8S Audit implementation concatenated the key and cert PEM
			// files, however this seems to be unusual. Here we use the same concatenated files
			// for both key and cert, but we may want to split them (this seems to work though).
			err = s.ListenAndServeTLS(k.config.SSLCertificate, k.config.SSLCertificate)
		} else {
			err = s.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			errorChan <- err
		}
	}()

	// on close, shutdown the webserver gracefully with, and wait for it with a timeout
	onClose := func() {
		timedCtx, cancelTimeoutCtx := context.WithTimeout(ctx, time.Second*webServerShutdownTimeoutSecs)
		defer cancelTimeoutCtx()
		s.Shutdown(timedCtx)
		cancelCtx()
	}

	// open the event source
	return k8saudit.OpenEventSource(ctx, eventChan, errorChan, k.config.TimeoutMillis, onClose)
}

func (k *K8SAuditPlugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", string(evtBytes)), nil
}
