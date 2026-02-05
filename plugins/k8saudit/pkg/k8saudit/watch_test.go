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
	"log"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

const testAuditEvent = `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"test","stage":"ResponseComplete","requestURI":"/api","verb":"get","user":{"username":"test"},"sourceIPs":["127.0.0.1"],"objectRef":{"resource":"pods","namespace":"default","name":"test"},"responseStatus":{"metadata":{},"code":200},"requestReceivedTimestamp":"2023-01-01T00:00:00.000000Z","stageTimestamp":"2023-01-01T00:00:01.000000Z"}`

// safeBuffer is a thread-safe buffer for capturing log output in tests.
type safeBuffer struct {
	mu  sync.Mutex
	buf []byte
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}

func newTestPlugin() (*Plugin, *safeBuffer) {
	p := &Plugin{}
	p.Config.Reset()
	buf := &safeBuffer{}
	p.logger = log.New(buf, "", 0)
	return p, buf
}

func TestOpenFileWatch_DetectsNewContent(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	if err := os.WriteFile(filePath, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	p, logBuf := newTestPlugin()
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
	// Write an invalid line; if the watcher reads the appended content,
	// parseAuditEventsAndPush logs a parse error proving the content was read.
	f.WriteString("SENTINEL\n")
	f.Close()

	time.Sleep(200 * time.Millisecond)

	if logBuf.String() == "" {
		t.Error("watcher did not process appended file content")
	}
}

func TestOpenFileWatch_HandlesRotation(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	if err := os.WriteFile(filePath, []byte(testAuditEvent+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p, logBuf := newTestPlugin()
	inst, err := p.OpenFileWatch(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.(sdk.Closer).Close()

	time.Sleep(100 * time.Millisecond)

	// Simulate rotation: remove and recreate
	os.Remove(filePath)
	if err := os.WriteFile(filePath, []byte("SENTINEL\n"), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

	if logBuf.String() == "" {
		t.Error("watcher did not process rotated file content")
	}
}

func TestOpenFileWatch_HandlesTruncation(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	// Write two events so the initial offset is large
	if err := os.WriteFile(filePath, []byte(testAuditEvent+"\n"+testAuditEvent+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p, logBuf := newTestPlugin()
	inst, err := p.OpenFileWatch(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.(sdk.Closer).Close()

	time.Sleep(100 * time.Millisecond)

	// Truncate and rewrite with less data (simulates logrotate copytruncate).
	// Without truncation detection the watcher would seek past EOF and miss this.
	if err := os.WriteFile(filePath, []byte("SENTINEL\n"), 0644); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)

	if logBuf.String() == "" {
		t.Error("watcher did not detect file truncation")
	}
}

func TestOpen_FileScheme(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "audit.log")

	if err := os.WriteFile(filePath, []byte(testAuditEvent+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	p, _ := newTestPlugin()
	inst, err := p.Open("file://" + filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.(sdk.Closer).Close()
}
