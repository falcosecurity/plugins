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

package gcpaudit

import (
	"io"
	"strings"
	"testing"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

// testExtractRequest is a minimal sdk.ExtractRequest that records the value
// the plugin sets, so a test can assert on what Falco would actually see.
type testExtractRequest struct {
	field string
	value interface{}
}

func (t *testExtractRequest) FieldID() uint64                   { return 0 }
func (t *testExtractRequest) FieldType() uint32                 { return sdk.FieldTypeCharBuf }
func (t *testExtractRequest) Field() string                     { return t.field }
func (t *testExtractRequest) ArgKey() string                    { return "" }
func (t *testExtractRequest) ArgIndex() uint64                  { return 0 }
func (t *testExtractRequest) ArgPresent() bool                  { return false }
func (t *testExtractRequest) IsList() bool                      { return false }
func (t *testExtractRequest) SetValue(v interface{})            { t.value = v }
func (t *testExtractRequest) SetPtr(unsafe.Pointer)             {}
func (t *testExtractRequest) SetOffsetPtrs(_, _ unsafe.Pointer) {}
func (t *testExtractRequest) WantOffset() bool                  { return false }
func (t *testExtractRequest) SetValueOffset(_, _ uint32)        {}

// testEventReader is a minimal sdk.EventReader backed by a JSON string.
type testEventReader struct {
	num  uint64
	data string
}

func (t *testEventReader) EventNum() uint64      { return t.num }
func (t *testEventReader) Timestamp() uint64     { return 0 }
func (t *testEventReader) Reader() io.ReadSeeker { return strings.NewReader(t.data) }

// extractField runs the full Extract path for a single field on a single
// event, the same way the framework calls it.
//
// Event numbers start at 1. Extract caches the parsed event and skips
// re-parsing when evt.EventNum() equals the plugin's lastEventNum, whose zero
// value is 0, so a fresh Plugin would not parse an event numbered 0.
func extractField(t *testing.T, eventNum uint64, field, event string) string {
	t.Helper()

	p := &Plugin{}
	req := &testExtractRequest{field: field}
	if err := p.Extract(req, &testEventReader{num: eventNum + 1, data: event}); err != nil {
		t.Fatalf("Extract(%s): unexpected error: %v", field, err)
	}
	if req.value == nil {
		return ""
	}
	s, ok := req.value.(string)
	if !ok {
		t.Fatalf("Extract(%s): expected a string value, got %T", field, req.value)
	}
	return s
}

// The fixtures below are synthetic. They are modelled on the SetIamPolicy
// entry in Google's audit log reference
// (https://docs.cloud.google.com/logging/docs/audit/understanding-audit-logs#sample)
// and on the payload shapes described in #1351, trimmed to the fields the
// plugin reads. They are not captured production logs.

// serviceDataEvent is the generic IAM shape: google.iam.v1.logging.AuditData
// under protoPayload.serviceData. This covers project, folder, organization,
// service_account and gcs_bucket.
const serviceDataEvent = `{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "cloudresourcemanager.googleapis.com",
    "methodName": "SetIamPolicy",
    "serviceData": {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      "policyDelta": {
        "bindingDeltas": [
          {"action": "ADD", "role": "roles/owner", "member": "user:attacker@example.com"}
        ]
      }
    }
  },
  "resource": {"type": "project", "labels": {"project_id": "my-project"}}
}`

// gcsBucketEvent is the one resource type the previous code routed to the
// serviceData path. It is kept as a regression case because the field came
// back empty even here, see TestExtractPolicyDelta.
const gcsBucketEvent = `{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "storage.googleapis.com",
    "methodName": "storage.setIamPermissions",
    "serviceData": {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      "policyDelta": {
        "bindingDeltas": [
          {"action": "ADD", "role": "roles/storage.objectViewer", "member": "allUsers"}
        ]
      }
    }
  },
  "resource": {"type": "gcs_bucket", "labels": {"bucket_name": "my-bucket"}}
}`

// datasetChangeEvent is BigQuery's BigQueryAuditMetadata shape.
const datasetChangeEvent = `{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "bigquery.googleapis.com",
    "methodName": "google.iam.v1.IAMPolicy.SetIamPolicy",
    "metadata": {
      "@type": "type.googleapis.com/google.cloud.audit.BigQueryAuditMetadata",
      "datasetChange": {
        "bindingDeltas": [
          {"action": "REMOVE", "role": "roles/bigquery.dataViewer", "member": "user:someone@example.com"}
        ]
      }
    }
  },
  "resource": {"type": "bigquery_dataset", "labels": {"project_id": "my-project"}}
}`

// metadataPolicyDeltaEvent carries the IAM AuditData under the newer metadata
// field instead of the deprecated serviceData field.
const metadataPolicyDeltaEvent = `{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "iam.googleapis.com",
    "methodName": "SetIamPolicy",
    "metadata": {
      "@type": "type.googleapis.com/google.iam.v1.logging.AuditData",
      "policyDelta": {
        "bindingDeltas": [
          {"action": "ADD", "role": "roles/iam.serviceAccountTokenCreator", "member": "user:attacker@example.com"}
        ]
      }
    }
  },
  "resource": {"type": "service_account", "labels": {"email_id": "sa@my-project.iam.gserviceaccount.com"}}
}`

// emptyServiceDataEvent is the stripped-on-export case: the serviceData
// wrapper survives but policyDelta does not, and no metadata is present.
const emptyServiceDataEvent = `{
  "protoPayload": {
    "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
    "serviceName": "cloudresourcemanager.googleapis.com",
    "methodName": "SetIamPolicy",
    "serviceData": {"@type": "type.googleapis.com/google.iam.v1.logging.AuditData"}
  },
  "resource": {"type": "organization", "labels": {}}
}`

// TestExtractPolicyDelta guards the actual symptom in #1351: gcp.policyDelta
// came back empty for every resource type that uses the generic IAM
// SetIamPolicy flow, because the extractor only looked under
// metadata.datasetChange unless resource.type was gcs_bucket.
//
// It exercises Extract end to end rather than the path lookup alone, so it
// also covers the serialization step. bindingDeltas is a JSON array, and the
// generic tail of Extract calls GetStringBytes, which returns nil for any
// non-string value. Selecting the right path is necessary but not sufficient.
func TestExtractPolicyDelta(t *testing.T) {
	cases := []struct {
		name         string
		event        string
		wantContains []string
	}{
		{
			name:         "generic IAM serviceData",
			event:        serviceDataEvent,
			wantContains: []string{`"action":"ADD"`, `"role":"roles/owner"`, "attacker@example.com"},
		},
		{
			name:         "gcs_bucket serviceData",
			event:        gcsBucketEvent,
			wantContains: []string{`"action":"ADD"`, `"role":"roles/storage.objectViewer"`, "allUsers"},
		},
		{
			name:         "bigquery datasetChange",
			event:        datasetChangeEvent,
			wantContains: []string{`"action":"REMOVE"`, `"role":"roles/bigquery.dataViewer"`},
		},
		{
			name:         "IAM AuditData under metadata",
			event:        metadataPolicyDeltaEvent,
			wantContains: []string{`"action":"ADD"`, `"roles/iam.serviceAccountTokenCreator"`},
		},
	}

	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := extractField(t, uint64(i), "gcp.policyDelta", tc.event)
			if got == "" {
				t.Fatalf("gcp.policyDelta is empty; this is the #1351 symptom")
			}
			for _, want := range tc.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("gcp.policyDelta = %s, want it to contain %s", got, want)
				}
			}
		})
	}
}

// TestExtractPolicyDeltaAbsent checks that an event with no usable deltas
// yields an empty field and no error, rather than a partial or bogus value.
func TestExtractPolicyDeltaAbsent(t *testing.T) {
	events := map[string]string{
		"stripped serviceData": emptyServiceDataEvent,
		"unrelated event":      `{"protoPayload":{"methodName":"storage.buckets.get"},"resource":{"type":"gcs_bucket"}}`,
	}

	var i uint64
	for name, event := range events {
		t.Run(name, func(t *testing.T) {
			if got := extractField(t, i, "gcp.policyDelta", event); got != "" {
				t.Errorf("gcp.policyDelta = %q, want empty", got)
			}
		})
		i++
	}
}

// TestPolicyDeltaPathPriority pins the order the payload locations are probed
// in, so a BigQuery event that also carries an empty serviceData wrapper still
// resolves to datasetChange.
func TestPolicyDeltaPathPriority(t *testing.T) {
	const bothShapes = `{
	  "protoPayload": {
	    "serviceData": {"policyDelta": {"bindingDeltas": []}},
	    "metadata": {"datasetChange": {"bindingDeltas": [{"action": "ADD", "role": "roles/bigquery.admin"}]}}
	  },
	  "resource": {"type": "bigquery_dataset"}
	}`

	got := extractField(t, 0, "gcp.policyDelta", bothShapes)
	if !strings.Contains(got, "roles/bigquery.admin") {
		t.Errorf("gcp.policyDelta = %q, want the datasetChange deltas; an empty serviceData array must not win", got)
	}
}
