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
)

func newTestPlugin() *Plugin {
	return &Plugin{Logger: log.New(io.Discard, "", 0)}
}

func TestRunProcessorReportsError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := errors.New("checkpoint store: AuthenticationFailed")
	pushEventC := make(chan source.PushEvent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		newTestPlugin().runProcessor(ctx, func(context.Context) error { return runErr }, pushEventC)
	}()

	select {
	case evt := <-pushEventC:
		if !errors.Is(evt.Err, runErr) {
			t.Fatalf("expected an event wrapping %q, got error %v", runErr, evt.Err)
		}
		if evt.Data != nil {
			t.Fatalf("expected no data with the error, got %q", evt.Data)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the processor error was not reported")
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runProcessor did not return after reporting the error")
	}
}

func TestRunProcessorStopsSilentlyOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	pushEventC := make(chan source.PushEvent, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// like azeventhubs.Processor.Run, return nil once ctx is canceled
		newTestPlugin().runProcessor(ctx, func(ctx context.Context) error {
			<-ctx.Done()
			return nil
		}, pushEventC)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runProcessor did not return after the context was canceled")
	}
	select {
	case evt := <-pushEventC:
		t.Fatalf("expected no event on cancel, got %+v", evt)
	default:
	}
}

func TestRunProcessorDoesNotBlockOnCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// nobody reads pushEventC, as when the plugin is being closed
	pushEventC := make(chan source.PushEvent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		newTestPlugin().runProcessor(ctx, func(context.Context) error {
			return errors.New("processor failed")
		}, pushEventC)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runProcessor blocked on a canceled context")
	}
}
