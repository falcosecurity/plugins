package gcpaudit

import (
	"bytes"
	_ "embed"
	"io"
	"testing"
	"time"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/stretchr/testify/assert"
)

var (
	//go:embed test.json
	eventsJSON string
)

type InMemoryEventReader struct {
	Buffer       []byte
	ValEventNum  uint64
	ValTimestamp uint64
}

func (i *InMemoryEventReader) EventNum() uint64 {
	return i.ValEventNum
}

func (i *InMemoryEventReader) Timestamp() uint64 {
	return i.ValTimestamp
}

func (i *InMemoryEventReader) Reader() io.ReadSeeker {
	return bytes.NewReader(i.Buffer)
}

type testExtractRequest struct {
	fieldID    uint64
	fieldType  uint32
	field      string
	isList     bool
	argPresent bool
	argIndex   uint64
	argKey     string
}

type jsonData struct {
	fileName string
	content  string
}

func (t *testExtractRequest) FieldID() uint64 {
	return t.fieldID
}

func (t *testExtractRequest) FieldType() uint32 {
	return t.fieldType
}

func (t *testExtractRequest) Field() string {
	return t.field
}

func (t *testExtractRequest) ArgKey() string {
	return t.argKey
}

func (t *testExtractRequest) ArgIndex() uint64 {
	return t.argIndex
}

func (t *testExtractRequest) ArgPresent() bool {
	return t.argPresent
}

func (t *testExtractRequest) IsList() bool {
	return t.isList
}

func (t *testExtractRequest) SetValue(v interface{}) {

}

func (t *testExtractRequest) SetPtr(unsafe.Pointer) {

}

func fieldEntryToRequest(id uint64, field *sdk.FieldEntry, req *testExtractRequest) {
	req.fieldID = id
	req.field = field.Name
	req.isList = field.IsList
	if field.Type == "string" {
		req.fieldType = sdk.FieldTypeCharBuf
	} else {
		req.fieldType = sdk.FieldTypeUint64
	}
	req.argPresent = false
	if field.Arg.IsIndex {
		req.argPresent = true
		req.argIndex = 0
	} else if field.Arg.IsKey {
		req.argPresent = true
		req.argKey = "sample"
	}
}

func TestExtractor_SampleFile(t *testing.T) {
	req := &testExtractRequest{}
	e := &Plugin{}
	fields := e.Fields()

	for idx, field := range fields {
		fieldEntryToRequest(uint64(idx), &field, req)
		reader := &InMemoryEventReader{
			Buffer:       []byte(eventsJSON),
			ValEventNum:  uint64(idx),
			ValTimestamp: uint64(time.Now().UnixNano()),
		}

		ret := e.Extract(req, reader)
		assert.Nil(t, ret, field)
	}
}
