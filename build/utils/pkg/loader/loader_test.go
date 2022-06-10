//go:build (linux && cgo) || (darwin && cgo) || (freebsd && cgo)
// +build linux,cgo darwin,cgo freebsd,cgo

/*
Copyright (C) 2022 The Falco Authors.

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

package loader

import (
	"testing"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
)

func strSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func infoEqual(a, b *plugins.Info) bool {
	return a.Version == b.Version &&
		a.RequiredAPIVersion == b.RequiredAPIVersion &&
		a.Name == b.Name &&
		a.Contact == b.Contact &&
		a.Description == b.Description &&
		a.ID == b.ID &&
		a.EventSource == b.EventSource &&
		strSliceEqual(a.ExtractEventSources, b.ExtractEventSources)
}

func TestLoading(t *testing.T) {
	_, err := NewPlugin("invalid path")
	if err == nil {
		t.Fatalf("expected non-nil error")
	}
	_, err = NewPlugin("../../test/sample/libsample.so")
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestInfo(t *testing.T) {
	p, err := NewPlugin("../../test/sample/libsample.so")
	if err != nil {
		t.Fatal(err.Error())
	}

	expectedInfo := plugins.Info{
		ID:                  999,
		Name:                "sample",
		Description:         "Sample",
		Contact:             "github.com/falcosecurity/plugins/",
		Version:             "0.0.1",
		EventSource:         "sample",
		RequiredAPIVersion:  "1.0.0",
		ExtractEventSources: []string{"sample", "sample2"},
	}
	actualInfo := p.Info()
	if err != nil {
		t.Fatal(err.Error())
	}
	if !infoEqual(actualInfo, &expectedInfo) {
		t.Fatalf("info does not match expected content")
	}
	actualInitSchema := p.InitSchema()
	if actualInitSchema == nil || actualInitSchema.Schema != "test schema" {
		t.Fatalf("init schema does not match expected content: %s", actualInitSchema.Schema)
	}
}

func TestInitDestroy(t *testing.T) {
	p, err := NewPlugin("../../test/sample/libsample.so")
	if err != nil {
		t.Fatal(err.Error())
	}

	err = p.Init("bad config")
	if err == nil || err.Error() != "test init error" {
		p.Destroy()
		t.Fatalf("expected non-nil error")
	}
	p.Destroy()

	err = p.Init("test config")
	defer p.Destroy()
	if err != nil {
		t.Fatal(err.Error())
	}
}
