// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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
package helpers

import (
	"bytes"
	"io"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

type MockWriter struct {
	Timestamp uint64
	Buffer    *bytes.Buffer
}

func (m *MockWriter) Writer() io.Writer {
	return m.Buffer
}

func (m *MockWriter) SetTimestamp(value uint64) {
	m.Timestamp = value
}

// MockWriters asts as an instance of sdk.EventWriters under test
type MockWriters struct {
	Writers []sdk.EventWriter
}

func (m MockWriters) Get(eventIndex int) sdk.EventWriter {
	return m.Writers[eventIndex]
}

func (m MockWriters) Len() int {
	return len(m.Writers)
}

func (m MockWriters) ArrayPtr() unsafe.Pointer {
	//TODO implement me
	panic("implement me")
}

func (m MockWriters) Free() {
	//TODO implement me
	panic("implement me")
}
