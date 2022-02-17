package json

import (
	"io"
	"strings"
	"testing"
	"time"
)

type testEventReader struct {
	num      uint64
	jsonData string
	time     time.Time
}

func (t *testEventReader) EventNum() uint64 {
	return t.num
}

func (t *testEventReader) Timestamp() uint64 {
	return uint64(t.time.UnixNano())
}

func (t *testEventReader) Reader() io.ReadSeeker {
	return strings.NewReader(t.jsonData)
}

func TestValue(t *testing.T) {
	testEvent := &testEventReader{
		num:  1,
		time: time.Now(),
		jsonData: `{
			"list":[
				{
					"intvalue":1,
					"floatvalue":2.5
				}
			],
			"value":"hello",
			"~/escaped":"hello2"
		}`,
	}
	e := &Extractor{}
	e.SetEventReader(testEvent)

	// invalid json pointer
	_, err := e.ValueStr("invalid_pointer")
	if err != ErrValueNotFound {
		if err == nil {
			t.Error("unexpected nil error for invalid pointer")
		} else {
			t.Error(err)
		}
	}

	// valid json pointer with string value
	str, err := e.ValueStr("/value")
	if err != nil {
		t.Error(err)
	}
	if str != "hello" {
		t.Errorf("expected value %s, but found %s", "hello", str)
	}

	// valid json pointer with u64 value and nesting
	num, err := e.ValueU64("/list/0/intvalue")
	if err != nil {
		t.Error(err)
	}
	if num != uint64(1) {
		t.Errorf("expected value %d, but found %d", uint64(1), num)
	}

	// valid json pointer with u64 value, nesting, and float conversion
	num, err = e.ValueU64("/list/0/floatvalue")
	if err != nil {
		t.Error(err)
	}
	if num != uint64(2) {
		t.Errorf("expected value %d, but found %d", uint64(2), num)
	}

	// valid json pointer with string value, nesting, and int conversion
	str, err = e.ValueStr("/list/0/intvalue")
	if err != nil {
		t.Error(err)
	}
	if str != "1" {
		t.Errorf("expected value %s, but found %s", "1", str)
	}

	// valid json pointer with u64 value and string conversion (should fail)
	_, err = e.ValueU64("/value")
	if err == nil {
		t.Error("unexpected nil error for invalid pointer")
	}

	// valid string json with escaped pointer
	str, err = e.ValueStr("/~0~1escaped")
	if err != nil {
		t.Error(err)
	}
	if str != "hello2" {
		t.Errorf("expected value %s, but found %s", "hello2", str)
	}
}
