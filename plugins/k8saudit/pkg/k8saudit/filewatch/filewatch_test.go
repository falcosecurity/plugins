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

package filewatch_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugins/plugins/k8saudit/pkg/k8saudit"
)

const testAuditEvent = `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"test","stage":"ResponseComplete","requestURI":"/api","verb":"get","user":{"username":"test"},"sourceIPs":["127.0.0.1"],"objectRef":{"resource":"pods","namespace":"default","name":"test"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2023-01-01T00:00:00.000000Z","stageTimestamp":"2023-01-01T00:00:01.000000Z"}`

func newTestPlugin() *k8saudit.Plugin {
	p := &k8saudit.Plugin{}
	p.Config.Reset()
	return p
}

func TestOpenFileWatch_DetectsNewContent(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	if err := os.WriteFile(filePath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	p := newTestPlugin()
	inst, err := p.OpenFileWatch(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.(sdk.Closer).Close()

	time.Sleep(100 * time.Millisecond)
	f, err := os.OpenFile(filePath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(testAuditEvent + "\n")
	f.Close()

	time.Sleep(200 * time.Millisecond)
}

func TestOpenFileWatch_HandlesRotation(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	if err := os.WriteFile(filePath, []byte(testAuditEvent+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p := newTestPlugin()
	inst, err := p.OpenFileWatch(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.(sdk.Closer).Close()

	time.Sleep(100 * time.Millisecond)

	os.Remove(filePath)
	if err := os.WriteFile(filePath, []byte(testAuditEvent+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)
}

func TestOpen_FileScheme(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	if err := os.WriteFile(filePath, []byte(testAuditEvent+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p := newTestPlugin()
	inst, err := p.Open("file://" + filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.(sdk.Closer).Close()
}
