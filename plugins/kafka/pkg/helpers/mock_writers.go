package helpers

import (
	"bytes"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"io"
	"unsafe"
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
