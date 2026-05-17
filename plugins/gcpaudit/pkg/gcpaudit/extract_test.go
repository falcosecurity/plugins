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
	"reflect"
	"testing"
)

// TestPolicyDeltaPath guards against #1351: gcp.policyDelta was returning the
// BigQuery datasetChange path for every non-gcs_bucket resource type, leaving
// the field empty for project, folder, organization, service_account, and any
// other GCP resource that uses the generic IAM SetIamPolicy flow.
func TestPolicyDeltaPath(t *testing.T) {
	serviceData := []string{"protoPayload", "serviceData", "policyDelta", "bindingDeltas"}
	datasetChange := []string{"protoPayload", "metadata", "datasetChange", "bindingDeltas"}

	cases := []struct {
		resource string
		want     []string
	}{
		{"gcs_bucket", serviceData},
		{"project", serviceData},
		{"folder", serviceData},
		{"organization", serviceData},
		{"service_account", serviceData},
		// Unknown / future resource types default to the generic IAM path,
		// not the BigQuery-specific datasetChange path.
		{"unknown_type", serviceData},
		{"", serviceData},
		{"bigquery_dataset", datasetChange},
	}

	for _, tc := range cases {
		t.Run(tc.resource, func(t *testing.T) {
			got := policyDeltaPath(tc.resource)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("policyDeltaPath(%q) = %v, want %v", tc.resource, got, tc.want)
			}
		})
	}
}
