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
	"context"
	"fmt"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/valyala/fastjson"
)

var defaultEventTimeout = 10 * time.Millisecond

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

// OpenEventSource opens the K8S Audit Logs event source returns a
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
func OpenEventSource(ctx context.Context, eventChan <-chan []byte, errorChan <-chan error, onClose func()) (source.Instance, error) {
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
				values, err := parseJSONMessage(jsonValue)
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

func parseJSONMessage(value *fastjson.Value) ([]*auditEvent, error) {
	if value == nil {
		return nil, fmt.Errorf("can't parse nil JSON message")
	}
	if value.Type() == fastjson.TypeArray {
		var res []*auditEvent
		for _, v := range value.GetArray() {
			values, err := parseJSONMessage(v)
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
					event, err := parseJSONAuditEvent(item)
					if err != nil {
						return nil, err
					}
					res = append(res, event)
				}
				return res, nil
			}
		case "Event":
			event, err := parseJSONAuditEvent(value)
			if err != nil {
				return nil, err
			}
			return []*auditEvent{event}, nil
		}
	}
	return nil, fmt.Errorf("data not recognized as a k8s audit event")
}

func parseJSONAuditEvent(value *fastjson.Value) (*auditEvent, error) {
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
