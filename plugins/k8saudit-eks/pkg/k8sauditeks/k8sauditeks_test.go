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

package k8sauditeks

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A fake CloudWatch Logs endpoint is reached through the SDK's own endpoint
// override, so Plugin.Open runs unchanged.
func TestOpenShiftIsSeconds(t *testing.T) {
	startTimes := make(chan int64, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("X-Amz-Target") != "Logs_20140328.FilterLogEvents" {
			http.Error(w, "unexpected request", http.StatusBadRequest)
			return
		}
		var req struct {
			StartTime int64 `json:"startTime"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		select {
		case startTimes <- req.StartTime:
		default:
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_, _ = w.Write([]byte(`{"events":[]}`))
	}))
	defer srv.Close()

	t.Setenv("AWS_ENDPOINT_URL_CLOUDWATCH_LOGS", srv.URL)
	t.Setenv("AWS_ACCESS_KEY_ID", "test")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test")
	t.Setenv("AWS_REGION", "us-east-1")
	t.Setenv("AWS_PROFILE", "")
	t.Setenv("AWS_DEFAULT_PROFILE", "")
	t.Setenv("AWS_CONFIG_FILE", "/dev/null")
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")

	p := &Plugin{}
	if err := p.Init(`{"shift": 10, "polling_interval": 1}`); err != nil {
		t.Fatal(err)
	}
	before := time.Now()
	inst, err := p.Open("test-cluster")
	if err != nil {
		t.Fatal(err)
	}
	defer inst.(interface{ Close() }).Close()

	select {
	case got := <-startTimes:
		lo := before.Add(-11 * time.Second).UnixMilli()
		hi := time.Now().Add(-9 * time.Second).UnixMilli()
		if got < lo || got > hi {
			t.Fatalf("first StartTime is %d ms ago, want 10s ago",
				time.Now().UnixMilli()-got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no FilterLogEvents request reached the fake endpoint")
	}
}
