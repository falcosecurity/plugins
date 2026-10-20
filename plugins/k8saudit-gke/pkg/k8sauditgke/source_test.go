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

package k8sauditgke

import (
	"testing"

	logging "cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/genproto/googleapis/api/monitoredres"
	"google.golang.org/genproto/googleapis/cloud/audit"
)

func auditLogEntry() *logging.LogEntry {
	return &logging.LogEntry{
		LogName:  "projects/falco/logs/cloudaudit.googleapis.com%2Factivity",
		InsertId: "insert-id",
		Resource: &monitoredres.MonitoredResource{
			Type:   "k8s_cluster",
			Labels: map[string]string{"cluster_name": "test"},
		},
	}
}

// requestMetadata and authenticationInfo are optional in an AuditLog, so an
// entry can reach the conversion without them.
func TestProcessAuditLogEntryWithoutRequestMetadata(t *testing.T) {
	p := &Plugin{}
	p.Config.Reset()

	auditLog := &audit.AuditLog{
		ServiceName:  "k8s.io",
		MethodName:   "io.k8s.core.v1.pods.get",
		ResourceName: "core/v1/namespaces/default/pods/nginx",
	}

	event, err := p.processAuditLogEntry(auditLogEntry(), auditLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(event.Data) == 0 {
		t.Fatal("expected event data")
	}
}

func TestIsValidLogEntryWithoutResource(t *testing.T) {
	entry := auditLogEntry()
	entry.Resource = nil
	if isValidLogEntry(entry) {
		t.Fatal("expected an entry without a resource to be rejected")
	}
}
