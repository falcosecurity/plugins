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
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/valyala/fastjson"
)

var defaultEventTimeout = 10 * time.Millisecond

const (
	webServerParamRgxStr         = "^(localhost)?(:[0-9]+)(\\/[.\\-\\w]+)$"
	webServerShutdownTimeoutSecs = 5
	webServerEventChanBufSize    = 50
)

type auditEvent struct {
	Data      *fastjson.Value
	Timestamp time.Time
}

type eventSource struct {
	source.BaseInstance
	eventChan <-chan *auditEvent
	errorChan <-chan error
	ctx       context.Context
	cancel    func()
	eof       bool
}

func (k *Plugin) Open(params string) (source.Instance, error) {
	if strings.HasPrefix(params, "file://") {
		return k.OpenFilePath(params[len("file://"):])
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
		// by default, fallback to opening a filepath
		return k.OpenFilePath(params)
	}
	matches := webServerParamRgx.FindStringSubmatch(webServerParam)
	if matches == nil || len(matches) != 4 {
		return nil, fmt.Errorf("webserver parameter does not match the regex '%s': %s", webServerParamRgxStr, webServerParam)
	}
	return k.OpenWebServer(matches[2], matches[3], ssl)
}

// OpenFilePath opens parameters with "file://" prefix, which represent one
// or more JSON objects encoded with JSONLine notation in a file on the
// local filesystem. Each JSON object produces an event in the returned
// event source.
func (k *Plugin) OpenFilePath(filePath string) (source.Instance, error) {
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
	return k.openEventSource(context.Background(), eventChan, errorChan, nil)
}

// OpenWebServer opens parameters with "http://" and "https://" prefixes.
// Starts a webserver and listens for K8S Audit Event webhooks.
func (k *Plugin) OpenWebServer(port, endpoint string, ssl bool) (source.Instance, error) {
	ctx, cancelCtx := context.WithCancel(context.Background())
	eventChan := make(chan []byte, webServerEventChanBufSize)
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
	return k.openEventSource(ctx, eventChan, errorChan, onClose)
}

// todo: optimize this to cache by event number
func (k *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%v", string(evtBytes)), nil
}

// openEventSource opens the K8S Audit Logs event source returns a
// source.Instance. ctx is the context of the event source, so cancelling
// it will result in an EOF. EventChan is the channel from which the K8S
// Audit digests are received as raw bytes. For reference, this is the body
// of K8S Audit webhooks or dump files. ErrorChan is a channel that can be
// used to propagate errors in the event source. The event source returns the
// errors it receives, so any error would cause it to be closed by the
// framwork. TimeoutMillis is the time interval (in milliseconds) after
// which a sdk.Timeout error is returned by NextBatch when no new event is
// received during that timeframe. OnClose is a callback that is invoked when
// the event source is closed by the plugin framework.
func (k *Plugin) openEventSource(ctx context.Context, eventChan <-chan []byte, errorChan <-chan error, onClose func()) (source.Instance, error) {
	// Launch the parsing goroutine that receives raw byte messages.
	// One or more audit events can be extracted from each message.
	newEventChan := make(chan *auditEvent)
	newErrorChan := make(chan error)
	go func() {
		defer close(newEventChan)
		defer close(newErrorChan)
		for {
			select {
			case bytes, ok := <-eventChan:
				if !ok {
					return
				}
				jsonValue, err := fastjson.ParseBytes(bytes)
				if err != nil {
					newErrorChan <- err
					return
				}
				values, err := k.parseJSONMessage(jsonValue)
				if err != nil {
					newErrorChan <- err
					return
				}
				for _, v := range values {
					newEventChan <- v
				}
			case <-ctx.Done():
				return
			case err := <-errorChan:
				newErrorChan <- err
			}
		}
	}()

	// return event source
	return &eventSource{
		eof:       false,
		ctx:       ctx,
		eventChan: newEventChan,
		errorChan: newErrorChan,
		cancel:    onClose,
	}, nil
}

func (e *eventSource) Close() {
	if e.cancel != nil {
		e.cancel()
	}
}

func (e *eventSource) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	if e.eof {
		return 0, sdk.ErrEOF
	}

	i := 0
	timeout := time.After(defaultEventTimeout)
	for i < evts.Len() {
		select {
		// an event is received, so we add it in the batch
		case ev, ok := <-e.eventChan:
			if !ok {
				// event channel is closed, we reached EOF
				e.eof = true
				return i, sdk.ErrEOF
			}
			evt := evts.Get(i)
			evt.SetTimestamp(uint64(ev.Timestamp.UnixNano()))
			// todo: we may want to optimize this path.
			// First, we parse the JSON message using fastjson, then we extract
			// the subvalues for each audit event contained in the event, then
			// we marshal each of them in byte slices, and finally we copy those
			// bytes in the io.Writer. In this case, we are constrained by fastjson,
			// maybe we should consider using a different JSON package here.
			if _, err := evt.Writer().Write(ev.Data.MarshalTo(nil)); err != nil {
				return i, err
			}
			i++
		// timeout hits, so we flush a partial batch
		case <-timeout:
			return i, sdk.ErrTimeout
		// context has been canceled, so we exit
		case <-e.ctx.Done():
			e.eof = true
			return i, sdk.ErrEOF
		// an error occurs, so we exit
		case err, ok := <-e.errorChan:
			if !ok {
				err = sdk.ErrEOF
			}
			e.eof = true
			return i, err
		}
	}
	return i, nil
}

func (k *Plugin) parseJSONMessage(value *fastjson.Value) ([]*auditEvent, error) {
	if value == nil {
		return nil, fmt.Errorf("can't parse nil JSON message")
	}
	if value.Type() == fastjson.TypeArray {
		var res []*auditEvent
		for _, v := range value.GetArray() {
			values, err := k.parseJSONMessage(v)
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
				var res []*auditEvent
				for _, item := range items {
					event, err := k.parseJSONAuditEvent(item)
					if err != nil {
						return nil, err
					}
					res = append(res, event)
				}
				return res, nil
			}
		case "Event":
			event, err := k.parseJSONAuditEvent(value)
			if err != nil {
				return nil, err
			}
			return []*auditEvent{event}, nil
		}
	}
	return nil, fmt.Errorf("data not recognized as a k8s audit event")
}

func (k *Plugin) parseJSONAuditEvent(value *fastjson.Value) (*auditEvent, error) {
	stageTimestamp := value.Get("stageTimestamp")
	if stageTimestamp == nil {
		return nil, fmt.Errorf("can't read stageTimestamp")
	}
	timestamp, err := time.Parse(time.RFC3339Nano, string(stageTimestamp.GetStringBytes()))
	if err != nil {
		return nil, err
	}
	return &auditEvent{
		Timestamp: timestamp,
		Data:      value,
	}, nil
}
