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

package k8saudit

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
	"sort"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/valyala/fastjson"
)

const (
	webServerShutdownTimeoutSecs = 5
	webServerEventChanBufSize    = 50
)

func (k *Plugin) Open(params string) (source.Instance, error) {
	u, err := url.Parse(params)
	if err != nil {
		return nil, err
	}

	switch u.Scheme {
	case "http":
		return k.OpenWebServer(u.Host, u.Path, false)
	case "https":
		return k.OpenWebServer(u.Host, u.Path, true)
	case "": // by default, fallback to opening a filepath
		trimmed := strings.TrimSpace(params)

		fileInfo, err := os.Stat(trimmed)
		if err != nil {
			return nil, err
		}
		if !fileInfo.IsDir() {
			file, err := os.Open(trimmed)
			if err != nil {
				return nil, err
			}
			return k.OpenReader(file)
		}

		files, err := ioutil.ReadDir(trimmed)
		if err != nil {
			return nil, err
		}

		sort.Slice(files, func(i, j int) bool {
			return files[i].ModTime().Before(files[j].ModTime())
		})

		// open all files as reader
		results := []io.Reader{}
		for _, f := range files {
			if !f.IsDir() {
				auditFile, err := os.Open(trimmed + "/" + f.Name())
				if err != nil {
					return nil, err
				}
				results = append(results, auditFile)
				results = append(results, strings.NewReader("\n"))
			}
		}

		// concat the readers and wrap with a no-op Close method
		AllAuditFiles := io.NopCloser(io.MultiReader(results...))
		return k.OpenReader(AllAuditFiles)
	}

	return nil, fmt.Errorf(`scheme "%s" is not supported`, u.Scheme)
}

// OpenReader opens a source.Instance event stream that reads K8S Audit
// Events from a io.ReadCloser. Each Event is a JSON object encoded with
// JSONL notation (see: https://jsonlines.org/).
func (k *Plugin) OpenReader(r io.ReadCloser) (source.Instance, error) {
	evtC := make(chan source.PushEvent)

	go func() {
		defer close(evtC)
		var parser fastjson.Parser
		scanner := bufio.NewScanner(r)
		scanner.Split(bufio.ScanLines)
		for scanner.Scan() {
			line := scanner.Text()
			if len(line) > 0 {
				k.parseAuditEventsAndPush(&parser, ([]byte)(line), evtC)
			}
		}
		err := scanner.Err()
		if err != nil {
			evtC <- source.PushEvent{Err: err}
		}
	}()

	return source.NewPushInstance(
		evtC,
		source.WithInstanceClose(func() { r.Close() }),
		source.WithInstanceEventSize(uint32(k.Config.MaxEventSize)))
}

// OpenWebServer opens a source.Instance event stream that receives K8S Audit
// Events by starting a server and listening for JSON webhooks. The expected
// JSON format is the one of K8S API Server webhook backend
// (see: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#webhook-backend).
func (k *Plugin) OpenWebServer(address, endpoint string, ssl bool) (source.Instance, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	serverEvtChan := make(chan []byte, webServerEventChanBufSize)
	evtChan := make(chan source.PushEvent)

	// launch webserver gorountine. This listens for webhooks coming from
	// the k8s api server and sends every valid payload to serverEvtChan so
	// that an HTTP response can be sent as soon as possible. Each payload is
	// then parsed to extract the list of audit events contained by the
	// event-parser goroutine
	m := http.NewServeMux()
	s := &http.Server{Addr: address, Handler: m}
	sendBody := func(b []byte) {
		defer func() {
			if r := recover(); r != nil {
				k.logger.Println("request dropped while shutting down server ")
			}
		}()
		serverEvtChan <- b
	}
	m.HandleFunc(endpoint, func(w http.ResponseWriter, req *http.Request) {
		if req.Method != "POST" {
			http.Error(w, fmt.Sprintf("%s method not allowed", req.Method), http.StatusMethodNotAllowed)
			return
		}
		if !strings.Contains(req.Header.Get("Content-Type"), "application/json") {
			http.Error(w, "wrong Content Type", http.StatusBadRequest)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, int64(k.Config.WebhookMaxBatchSize))
		bytes, err := ioutil.ReadAll(req.Body)
		if err != nil {
			msg := fmt.Sprintf("bad request: %s", err.Error())
			k.logger.Println(msg)
			http.Error(w, msg, http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
		sendBody(bytes)
	})
	go func() {
		defer close(serverEvtChan)
		var err error
		if ssl {
			// note: the legacy K8S Audit implementation concatenated the key and cert PEM
			// files, however this seems to be unusual. Here we use the same concatenated files
			// for both key and cert, but we may want to split them (this seems to work though).
			err = s.ListenAndServeTLS(k.Config.SSLCertificate, k.Config.SSLCertificate)
		} else {
			err = s.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			evtChan <- source.PushEvent{Err: err}
		}
	}()

	// launch event-parser gorountine. This received webhook payloads
	// and parses their content to extract the list of audit events contained.
	// Then, events are sent to the Push-mode event source instance channel.
	go func() {
		defer close(evtChan)
		var parser fastjson.Parser
		for {
			select {
			case bytes, ok := <-serverEvtChan:
				if !ok {
					return
				}
				k.parseAuditEventsAndPush(&parser, bytes, evtChan)
			case <-ctx.Done():
				return
			}
		}
	}()

	// open new instance in with "push" prebuilt
	return source.NewPushInstance(
		evtChan,
		source.WithInstanceContext(ctx),
		source.WithInstanceClose(func() {
			// on close, attempt shutting down the webserver gracefully
			timedCtx, cancelTimeoutCtx := context.WithTimeout(ctx, time.Second*webServerShutdownTimeoutSecs)
			defer cancelTimeoutCtx()
			s.Shutdown(timedCtx)
			cancelCtx()
		}),
		source.WithInstanceEventSize(uint32(k.Config.MaxEventSize)),
	)
}

// todo: optimize this to cache by event number
func (k *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", string(evtBytes)), nil
}

// here we make all errors non-blocking for single events by
// simply logging them, to ensure consumers don't close the
// event source with bad or malicious payloads
func (k *Plugin) parseAuditEventsAndPush(parser *fastjson.Parser, payload []byte, c chan<- source.PushEvent) {
	data, err := parser.ParseBytes(payload)
	if err != nil {
		k.logger.Println(err.Error())
		return
	}
	values, err := k.ParseAuditEventsJSON(data)
	if err != nil {
		k.logger.Println(err.Error())
		return
	}
	for _, v := range values {
		if v.Err != nil {
			k.logger.Println(v.Err.Error())
			continue
		} else {
			c <- *v
		}
	}
}

// ParseAuditEventsPayload parses a byte slice representing a JSON payload
// that contains one or more K8S Audit Events. If the payload is parsed
// correctly, returns the slice containing all the events parsed and a nil error.
// A nil slice and a non-nil error is returned in case the parsing fails.
//
// Even if a nil error is returned, each of the events of the returned slice can
// still contain an error (source.PushEvent.Err is non-nil). The reason is that
// if a single event is corrupted, this function still attempts to parse the
// rest of the events in the payload.
func (k *Plugin) ParseAuditEventsPayload(payload []byte) ([]*source.PushEvent, error) {
	value, err := fastjson.ParseBytes(payload)
	if err != nil {
		return nil, err
	}
	return k.ParseAuditEventsJSON(value)
}

// ParseAuditEventsJSON is the same as ParseAuditEventsPayload, but takes
// a pre-parsed JSON as input. The JSON representation is the one of the
// fastjson library.
func (k *Plugin) ParseAuditEventsJSON(value *fastjson.Value) ([]*source.PushEvent, error) {
	if value == nil {
		return nil, fmt.Errorf("can't parse nil JSON message")
	}
	if value.Type() == fastjson.TypeArray {
		var res []*source.PushEvent
		for _, v := range value.GetArray() {
			values, err := k.ParseAuditEventsJSON(v)
			if err != nil {
				return res, err
			}
			res = append(res, values...)
		}
		return res, nil
	} else if value.Get("kind") != nil && value.Get("kind").GetStringBytes() != nil {
		switch string(value.Get("kind").GetStringBytes()) {
		case "EventList":
			items := value.Get("items").GetArray()
			if items != nil {
				var res []*source.PushEvent
				for _, item := range items {
					res = append(res, k.parseSingleAuditEventJSON(item))
				}
				return res, nil
			}
		case "Event":
			return []*source.PushEvent{k.parseSingleAuditEventJSON(value)}, nil
		}
	}
	return nil, fmt.Errorf("data not recognized as a k8s audit event")
}

func (k *Plugin) parseSingleAuditEventJSON(value *fastjson.Value) *source.PushEvent {
	res := &source.PushEvent{}
	stageTimestamp := value.Get("stageTimestamp")
	if stageTimestamp == nil {
		res.Err = fmt.Errorf("can't read stageTimestamp")
		return res
	}
	timestamp, err := time.Parse(time.RFC3339Nano, string(stageTimestamp.GetStringBytes()))
	if err != nil {
		res.Err = err
		return res
	}
	res.Data = value.MarshalTo(nil)
	if len(res.Data) > int(k.Config.MaxEventSize) {
		res.Err = fmt.Errorf("event larger than maxEventSize: size=%d", len(res.Data))
		res.Data = nil
		return res
	}
	res.Timestamp = timestamp
	return res
}
