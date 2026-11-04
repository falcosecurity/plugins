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

package k8sauditaks

import (
	"context"
	"errors"
	"io"
	"log"
	"testing"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	falcoeventhub "github.com/falcosecurity/plugins/shared/go/azure/eventhub"
)

// newTestPlugin returns a Plugin ready to drive runRecordPump: a discard
// logger and an embedded k8saudit.Plugin configured the same way Init()
// configures it (MaxEventSize defaulted so valid events aren't rejected as
// oversized).
func newTestPlugin(t *testing.T) *Plugin {
	t.Helper()
	p := &Plugin{Logger: log.New(io.Discard, "", 0)}
	p.Plugin.Config.Reset()
	return p
}

func TestRunRecordPumpValidEvent(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsC := make(chan falcoeventhub.Record)
	pushEventC := make(chan source.PushEvent)
	p.runRecordPump(ctx, eventsC, nil, pushEventC)

	go func() {
		eventsC <- falcoeventhub.Record{Properties: struct {
			Log string `json:"log"`
		}{Log: `{"kind":"Event","stageTimestamp":"2024-01-01T00:00:00.000000Z"}`}}
	}()

	select {
	case evt := <-pushEventC:
		if evt.Err != nil {
			t.Fatalf("unexpected event error: %v", evt.Err)
		}
		if len(evt.Data) == 0 {
			t.Fatalf("expected non-empty event data")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for the pushed event")
	}
}

func TestRunRecordPumpSkipsNonJSONLog(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsC := make(chan falcoeventhub.Record)
	pushEventC := make(chan source.PushEvent)
	p.runRecordPump(ctx, eventsC, nil, pushEventC)

	// AKS diagnostic settings can route non-kube-audit categories
	// (kube-apiserver, cluster-autoscaler, ...) to the same EventHub; those
	// carry klog plain text instead of JSON and must be silently skipped.
	go func() {
		eventsC <- falcoeventhub.Record{Properties: struct {
			Log string `json:"log"`
		}{Log: "I0101 00:00:00.000000       1 controller.go:100] plain klog text"}}
	}()

	assertNoPush(t, pushEventC)
}

func TestRunRecordPumpSkipsUnparseableAuditEvent(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsC := make(chan falcoeventhub.Record)
	pushEventC := make(chan source.PushEvent)
	p.runRecordPump(ctx, eventsC, nil, pushEventC)

	// Valid JSON, but not a recognizable k8s audit event (no "kind").
	go func() {
		eventsC <- falcoeventhub.Record{Properties: struct {
			Log string `json:"log"`
		}{Log: `{"foo":"bar"}`}}
	}()

	assertNoPush(t, pushEventC)
}

func TestRunRecordPumpStopsOnChannelClose(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsC := make(chan falcoeventhub.Record)
	pushEventC := make(chan source.PushEvent)
	wg := p.runRecordPump(ctx, eventsC, nil, pushEventC)

	close(eventsC)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runRecordPump goroutine did not exit after eventsC was closed")
	}
}

// TestRunRecordPumpPropagatesUnrecoverableError covers the case where a
// producer (e.g. the Kafka reader) hits an unrecoverable error and closes
// eventsC because of it, rather than because of a clean shutdown. Before
// this was fixed, runRecordPump treated that identically to a clean close
// and returned silently: pushEventC then just went quiet forever, so
// Falco kept getting sdk.ErrTimeout instead of being told the source had
// failed. errC is how the producer tells runRecordPump which case it is.
func TestRunRecordPumpPropagatesUnrecoverableError(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsC := make(chan falcoeventhub.Record)
	errC := make(chan error, 1)
	pushEventC := make(chan source.PushEvent)
	p.runRecordPump(ctx, eventsC, errC, pushEventC)

	wantErr := errors.New("kafka: boom")
	// Mirrors the real producer: send to errC, then close eventsC.
	errC <- wantErr
	close(eventsC)

	select {
	case evt := <-pushEventC:
		if !errors.Is(evt.Err, wantErr) {
			t.Fatalf("got PushEvent.Err %v, want %v", evt.Err, wantErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for the error to be propagated to pushEventC")
	}
}

// TestRunRecordPumpCleanCloseReportsNoError confirms the ordinary shutdown
// path (eventsC closed, nothing on errC) still exits quietly, without a
// spurious PushEvent.
func TestRunRecordPumpCleanCloseReportsNoError(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsC := make(chan falcoeventhub.Record)
	errC := make(chan error, 1)
	pushEventC := make(chan source.PushEvent)
	wg := p.runRecordPump(ctx, eventsC, errC, pushEventC)

	close(eventsC)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runRecordPump goroutine did not exit after eventsC was closed")
	}
	assertNoPush(t, pushEventC)
}

func TestRunRecordPumpStopsOnContextCancel(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())

	eventsC := make(chan falcoeventhub.Record)
	pushEventC := make(chan source.PushEvent)
	wg := p.runRecordPump(ctx, eventsC, nil, pushEventC)

	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runRecordPump goroutine did not exit after ctx was canceled")
	}
}

func TestRunRecordPumpPushIsCancellationAware(t *testing.T) {
	p := newTestPlugin(t)
	ctx, cancel := context.WithCancel(context.Background())

	eventsC := make(chan falcoeventhub.Record)
	// Nobody ever reads from pushEventC: a plain `pushEventC <- *j` send
	// would block forever here, the way Falco not draining it during
	// shutdown would. The pump must still exit once ctx is canceled.
	pushEventC := make(chan source.PushEvent)
	wg := p.runRecordPump(ctx, eventsC, nil, pushEventC)

	go func() {
		eventsC <- falcoeventhub.Record{Properties: struct {
			Log string `json:"log"`
		}{Log: `{"kind":"Event","stageTimestamp":"2024-01-01T00:00:00.000000Z"}`}}
	}()

	// Give the pump a moment to parse the record and reach the blocked
	// send to pushEventC before canceling.
	time.Sleep(50 * time.Millisecond)
	cancel()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("runRecordPump did not exit after ctx was canceled while blocked sending to pushEventC")
	}
}

// assertNoPush fails the test if a source.PushEvent arrives on pushEventC
// within a short grace period, used to confirm a record was silently
// dropped rather than propagated.
func assertNoPush(t *testing.T, pushEventC <-chan source.PushEvent) {
	t.Helper()
	select {
	case evt := <-pushEventC:
		t.Fatalf("expected no event to be pushed, got %+v", evt)
	case <-time.After(200 * time.Millisecond):
	}
}
