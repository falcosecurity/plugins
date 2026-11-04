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

package eventhub

import (
	"context"
	"log"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func newTestProcessor() *Processor {
	return &Processor{
		RateLimiter: rate.NewLimiter(rate.Inf, 0),
		Logger:      log.New(log.Writer(), "", 0),
	}
}

func TestHandleEventPushesEachRecord(t *testing.T) {
	p := newTestProcessor()
	body := []byte(`{"records":[{"properties":{"log":"one"}},{"properties":{"log":"two"}}]}`)
	recordChan := make(chan Record, 2)

	if err := p.HandleEvent(context.Background(), body, recordChan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	close(recordChan)

	var got []string
	for r := range recordChan {
		got = append(got, r.Properties.Log)
	}
	if len(got) != 2 || got[0] != "one" || got[1] != "two" {
		t.Fatalf("got %v, want [one two]", got)
	}
}

func TestHandleEventInvalidJSON(t *testing.T) {
	p := newTestProcessor()
	recordChan := make(chan Record, 1)

	if err := p.HandleEvent(context.Background(), []byte("not json"), recordChan); err == nil {
		t.Fatalf("expected an error for invalid JSON")
	}
}

func TestHandleEventEmptyRecordsArray(t *testing.T) {
	p := newTestProcessor()
	recordChan := make(chan Record)

	if err := p.HandleEvent(context.Background(), []byte(`{"records":[]}`), recordChan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case r := <-recordChan:
		t.Fatalf("expected no record to be pushed, got %+v", r)
	default:
	}
}

func TestHandleEventNoRecordsField(t *testing.T) {
	p := newTestProcessor()
	recordChan := make(chan Record)

	if err := p.HandleEvent(context.Background(), []byte(`{}`), recordChan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case r := <-recordChan:
		t.Fatalf("expected no record to be pushed, got %+v", r)
	default:
	}
}

func TestHandleEventRateLimiterDropsRecordWithoutError(t *testing.T) {
	// A finite-rate limiter with zero burst can never admit a request:
	// Wait returns an error immediately (not a block), so HandleEvent must
	// treat that as "drop this record" and keep going, not fail the whole
	// event. (rate.Inf would ignore burst entirely, so it must not be used
	// here.)
	p := &Processor{
		RateLimiter: rate.NewLimiter(rate.Limit(1), 0),
		Logger:      log.New(log.Writer(), "", 0),
	}
	recordChan := make(chan Record)

	if err := p.HandleEvent(context.Background(), []byte(`{"records":[{"properties":{"log":"one"}}]}`), recordChan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case r := <-recordChan:
		t.Fatalf("expected the record to be dropped by the rate limiter, got %+v", r)
	default:
	}
}

func TestUnmarshallEventValid(t *testing.T) {
	event, err := UnmarshallEvent([]byte(`{"records":[{"properties":{"log":"one"}},{"properties":{"log":"two"}}]}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(event.Records) != 2 || event.Records[0].Properties.Log != "one" || event.Records[1].Properties.Log != "two" {
		t.Fatalf("got %+v, want two records [one two]", event.Records)
	}
}

func TestUnmarshallEventInvalid(t *testing.T) {
	if _, err := UnmarshallEvent([]byte("not json")); err == nil {
		t.Fatalf("expected an error for invalid JSON")
	}
}

func TestHandleEventRespectsContextCancellation(t *testing.T) {
	p := newTestProcessor()
	body := []byte(`{"records":[{"properties":{"log":"one"}}]}`)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// recordChan has no reader and no buffer, so without the ctx.Done()
	// case HandleEvent would block forever here.
	recordChan := make(chan Record)
	done := make(chan error, 1)
	go func() { done <- p.HandleEvent(ctx, body, recordChan) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("HandleEvent did not return after context cancellation")
	}
}
