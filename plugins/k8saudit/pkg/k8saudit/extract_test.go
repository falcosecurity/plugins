package k8saudit

import (
	"bufio"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
)

type testExtractRequest struct {
	fieldID    uint64
	fieldType  uint32
	field      string
	isList     bool
	argPresent bool
	argIndex   uint64
	argKey     string
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

func readTestFiles(b testing.TB) []string {
	path := "../../test_files/"
	files, err := ioutil.ReadDir(path)
	if err != nil {
		b.Error(err)
	}
	jsons := make([]string, 0, len(files))
	for _, f := range files {
		if strings.HasSuffix(f.Name(), ".json") {
			file, err := os.Open(path + f.Name())
			if err != nil {
				b.Errorf("opening file %s: %s", f.Name(), err.Error())
			}
			scanner := bufio.NewScanner(file)
			for scanner.Scan() {
				if len(scanner.Text()) > 0 {
					jsons = append(jsons, scanner.Text())
				}
			}
			if err := scanner.Err(); err != nil {
				b.Errorf("reading file %s: %s", f.Name(), err.Error())
			}
			file.Close()
		}
	}
	return jsons
}

func BenchmarkExtractFromJSON(b *testing.B) {
	req := &testExtractRequest{}
	e := &AuditEventExtractor{}
	fields := Fields()
	jsons := readTestFiles(b)

	b.ResetTimer()
	exCount := 0
	start := time.Now()
	for i := 0; i < b.N; i++ {
		for ev, data := range jsons {
			for f, field := range fields {
				fieldEntryToRequest(uint64(f), &field, req)
				json, err := e.Decode(uint64(ev), strings.NewReader(data))
				if err != nil && err != ErrExtractNotAvailable {
					b.Errorf("decoding field %s: %s", field.Name, err.Error())
				}
				err = e.ExtractFromJSON(req, json)
				if err != nil && err != ErrExtractNotAvailable {
					b.Errorf("extracting field %s: %s", field.Name, err.Error())
				}
				exCount++
			}
		}
	}
	exOp := float64(exCount) / float64(b.N)
	nsOp := float64(time.Since(start).Nanoseconds()) / float64(b.N)
	b.ReportMetric(exOp, "extractions/op")
	b.ReportMetric(nsOp/exOp, "ns/extraction/op")
}
