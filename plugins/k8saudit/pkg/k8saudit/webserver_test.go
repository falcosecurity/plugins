// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2026 The Falco Authors.

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
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

// The tests below leave nobody reading events until they choose to, so the event
// parser goroutine of OpenWebServer blocks on its unbuffered output channel. The
// parser does not watch the instance context there, so a parser blocked at Close
// leaks for the rest of the test binary. It holds no port and does not affect other
// tests.

const webServerTestEndpoint = "/k8s-audit"

type testWebServer struct {
	t    *testing.T
	plug *Plugin
	logs *safeBuffer
	inst source.Instance
	url  string
}

// startTestWebServer starts OpenWebServer on a free loopback port with the given
// webhookEnqueueTimeout in seconds and returns once the server answers. OpenWebServer takes an address and not a listener, so the port
// is free only when it is picked; if another process takes it first, the bind error
// arrives on the event channel and the server is started again on another port.
func startTestWebServer(t *testing.T, enqueueTimeout uint64) *testWebServer {
	t.Helper()
	for attempt := 0; attempt < 5; attempt++ {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}

		p, logs := newTestPlugin()
		p.Config.WebhookEnqueueTimeout = enqueueTimeout
		inst, err := p.OpenWebServer(addr, webServerTestEndpoint, false)
		if err != nil {
			t.Fatal(err)
		}
		s := &testWebServer{t: t, plug: p, logs: logs, inst: inst, url: "http://" + addr + webServerTestEndpoint}
		ready, err := s.waitReady()
		if ready {
			t.Cleanup(func() { inst.(sdk.Closer).Close() })
			return s
		}
		t.Logf("web server on %s did not start: %v", addr, err)
	}
	t.Fatal("web server did not start")
	return nil
}

// waitReady polls the endpoint with GET, which the handler answers with 405 without
// touching the queue. It returns false with the bind error if the server failed.
func (s *testWebServer) waitReady() (bool, error) {
	client := &http.Client{Timeout: time.Second}
	evts := &bufferEventWriters{}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := client.Get(s.url)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusMethodNotAllowed && strings.Contains(string(body), "GET method not allowed") {
				return true, nil
			}
			return false, fmt.Errorf("unexpected answer %d %q", resp.StatusCode, body)
		}
		// Not listening yet, or failed to listen: a failure is the only event the
		// instance can return here, since nothing has been posted.
		if _, err := s.inst.NextBatch(nil, evts); err != nil && !errors.Is(err, sdk.ErrTimeout) {
			return false, err
		}
	}
	return false, errors.New("timed out")
}

func (s *testWebServer) post(client *http.Client, auditID string) (*http.Response, time.Duration, error) {
	event := strings.Replace(testAuditEvent, `"auditID":"test"`, `"auditID":"`+auditID+`"`, 1)
	body := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[` + event + `]}`
	start := time.Now()
	resp, err := client.Post(s.url, "application/json", strings.NewReader(body))
	if err == nil {
		_ = resp.Body.Close()
	}
	return resp, time.Since(start), err
}

// fillQueue posts batches until the event queue is full: the parser takes the first
// one and blocks on the unread event channel, webServerEventChanBufSize more fill the
// queue. Every one of them must be accepted at once.
func (s *testWebServer) fillQueue() []string {
	client := &http.Client{Timeout: 15 * time.Second}
	var ids []string
	for i := 0; i <= webServerEventChanBufSize; i++ {
		id := fmt.Sprintf("queued-%d", i)
		resp, d, err := s.post(client, id)
		if err != nil {
			s.t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || d > time.Second {
			s.t.Fatalf("batch %d: status %d after %s, want 200 at once", i, resp.StatusCode, d)
		}
		ids = append(ids, id)
	}
	return ids
}

// readAuditIDs reads events from the instance until none arrives for idle and
// returns their audit IDs.
func (s *testWebServer) readAuditIDs(idle time.Duration) []string {
	evts := &bufferEventWriters{}
	var ids []string
	last := time.Now()
	for time.Since(last) < idle {
		n, err := s.inst.NextBatch(nil, evts)
		if err != nil && !errors.Is(err, sdk.ErrTimeout) {
			s.t.Fatal(err)
		}
		if n == 0 {
			continue
		}
		ids = append(ids, auditIDOf(s.t, evts.buf.Bytes()))
		last = time.Now()
	}
	return ids
}

// bufferEventWriters is a batch of one event kept in Go memory, so that a test can
// read back what the instance wrote.
type bufferEventWriters struct{ buf bytes.Buffer }

func (b *bufferEventWriters) Get(int) sdk.EventWriter  { return b }
func (b *bufferEventWriters) Len() int                 { return 1 }
func (b *bufferEventWriters) ArrayPtr() unsafe.Pointer { return nil }
func (b *bufferEventWriters) Free()                    {}
func (b *bufferEventWriters) SetTimestamp(uint64)      {}
func (b *bufferEventWriters) Writer() io.Writer        { b.buf.Reset(); return &b.buf }

func auditIDOf(t *testing.T, event []byte) string {
	t.Helper()
	const key = `"auditID":"`
	e := string(event)
	i := strings.Index(e, key)
	if i < 0 {
		t.Fatalf("no auditID in event %s", e)
	}
	e = e[i+len(key):]
	return e[:strings.Index(e, `"`)]
}

// postOverFullQueue fills the queue, posts one more batch and checks that it is
// refused with 429 without Retry-After after about want.
func postOverFullQueue(t *testing.T, s *testWebServer, want time.Duration) {
	t.Helper()
	s.fillQueue()

	resp, d, err := s.post(&http.Client{Timeout: 15 * time.Second}, "refused")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("batch over the queue: status %d after %s, want 429", resp.StatusCode, d)
	}
	if v := resp.Header.Get("Retry-After"); v != "" {
		t.Fatalf("429 with Retry-After %q, want none", v)
	}
	if d < want || d > want+2*time.Second {
		t.Fatalf("429 after %s, want about %s", d, want)
	}
	if !strings.Contains(s.logs.String(), "event queue is full, 1 webhook batches refused") {
		t.Fatalf("no log line about the full queue, log:\n%s", s.logs.String())
	}
}

// With the queue full, the webhook must refuse a batch with 429 after the default
// webhookEnqueueTimeout, and without Retry-After, so that the API server retries it
// with its exponential back-off instead of cancelling the request and sending it again.
func TestWebServerRefusesBatchesWhenQueueIsFull(t *testing.T) {
	var cfg PluginConfig
	cfg.Reset()
	s := startTestWebServer(t, cfg.WebhookEnqueueTimeout)
	postOverFullQueue(t, s, time.Duration(cfg.WebhookEnqueueTimeout)*time.Second)
}

// webhookEnqueueTimeout sets how long a batch waits for room in a full queue.
func TestWebServerEnqueueTimeout(t *testing.T) {
	for _, timeout := range []uint64{0, 1} {
		t.Run(fmt.Sprintf("%ds", timeout), func(t *testing.T) {
			s := startTestWebServer(t, timeout)
			postOverFullQueue(t, s, time.Duration(timeout)*time.Second)
		})
	}
}

func TestConfigWebhookEnqueueTimeout(t *testing.T) {
	for cfg, want := range map[string]uint64{
		`{}`:                          5,
		`{"webhookEnqueueTimeout":0}`: 0,
		`{"webhookEnqueueTimeout":2}`: 2,
	} {
		var p Plugin
		if err := p.Init(cfg); err != nil {
			t.Fatalf("Init(%s): %v", cfg, err)
		}
		if p.Config.WebhookEnqueueTimeout != want {
			t.Errorf("Init(%s): webhookEnqueueTimeout %d, want %d", cfg, p.Config.WebhookEnqueueTimeout, want)
		}
	}
	if schema := (&Plugin{}).InitSchema(); schema == nil || !strings.Contains(schema.Schema, `"webhookEnqueueTimeout"`) {
		t.Errorf("init schema does not describe webhookEnqueueTimeout: %v", schema)
	}
}

// A request the sender cancels while the queue is full must end at once and must
// not be queued later: the API server sends such a batch again, so queueing the
// cancelled copy would process it twice.
func TestWebServerDropsCancelledBatches(t *testing.T) {
	const enqueueTimeout = 5 * time.Second
	s := startTestWebServer(t, uint64(enqueueTimeout/time.Second))
	queued := s.fillQueue()

	const senderTimeout = time.Second
	start := time.Now()
	if _, _, err := s.post(&http.Client{Timeout: senderTimeout}, "cancelled"); err == nil {
		t.Fatal("request over the queue succeeded, want a client timeout")
	}
	const logLine = "1 webhook requests cancelled by the API server"
	for !strings.Contains(s.logs.String(), logLine) {
		if time.Since(start) > enqueueTimeout {
			t.Fatalf("handler still waits %s after the sender cancelled, log:\n%s", time.Since(start), s.logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if d := time.Since(start); d > senderTimeout+time.Second {
		t.Fatalf("handler ended %s after the request started, want about %s", d, senderTimeout)
	}

	// Free the queue: the cancelled batch must not follow the queued ones.
	got := s.readAuditIDs(time.Second)
	if strings.Join(got, ",") != strings.Join(queued, ",") {
		t.Fatalf("events after draining the queue:\n%v\nwant:\n%v", got, queued)
	}

	// The queue accepts batches again.
	resp, _, err := s.post(&http.Client{Timeout: 15 * time.Second}, "after")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("batch after draining: status %d, want 200", resp.StatusCode)
	}
	if got := s.readAuditIDs(time.Second); len(got) != 1 || got[0] != "after" {
		t.Fatalf("events after a new batch: %v, want [after]", got)
	}
}
