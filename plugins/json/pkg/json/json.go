package json

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/valyala/fastjson"
)

var (
	ErrValueNotFound = errors.New("json value not found")
)

type Extractor struct {
	evt        sdk.EventReader
	parser     fastjson.Parser
	lastEvtNum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	lastData   []byte
	lastValue  *fastjson.Value
}

func (e *Extractor) SetEventReader(v sdk.EventReader) {
	e.evt = v
}

func (e *Extractor) ValueStr(jsonPointer string) (string, error) {
	val, err := e.value(jsonPointer)
	if err != nil {
		return "", err
	}
	if val == nil {
		return "", ErrValueNotFound
	}
	if val.Type() == fastjson.TypeString {
		str, err := val.StringBytes()
		if err != nil {
			return "", err
		}
		return string(str), nil
	}
	return string(val.MarshalTo(nil)), nil
}

func (e *Extractor) ValueU64(jsonPointer string) (uint64, error) {
	val, err := e.value(jsonPointer)
	if err != nil {
		return 0, err
	}
	if val == nil {
		return 0, ErrValueNotFound
	}
	u64, err := val.Uint64()
	if err == nil {
		return u64, nil
	}
	f64, err := val.Float64()
	if err == nil {
		return uint64(f64), nil
	}
	return val.Uint64()
}

func (e *Extractor) ExtractValue(req sdk.ExtractRequest, jsonPointer string) error {
	var err error
	switch req.FieldType() {
	case sdk.ParamTypeCharBuf:
		v, err := e.ValueStr(jsonPointer)
		if err == nil {
			req.SetValue(v)
		}
	case sdk.ParamTypeUint64:
		v, err := e.ValueU64(jsonPointer)
		if err == nil {
			req.SetValue(v)
		}
	default:
		err = fmt.Errorf("unknwon extract request type")
	}
	if err != ErrValueNotFound {
		return err
	}
	return nil
}

func (e *Extractor) Object() (string, error) {
	if err := e.readData(); err != nil {
		return "", err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, e.lastData, "", "  "); err != nil {
		return "", err
	}
	return out.String(), nil
}

func (e *Extractor) ExtractObject(req sdk.ExtractRequest) error {
	v, err := e.Object()
	if err == nil {
		req.SetValue(v)
	}
	if err != ErrValueNotFound {
		return err
	}
	return nil
}

func (e *Extractor) value(jsonPointer string) (*fastjson.Value, error) {
	if err := e.readData(); err != nil {
		return nil, err
	}

	if len(jsonPointer) == 0 {
		return nil, fmt.Errorf("value argument is required")
	}
	if jsonPointer[0] == '/' {
		jsonPointer = jsonPointer[1:]
	}
	// walk the object using the json pointer syntax (RFC 6901)
	pointer := strings.Split(jsonPointer, "/")
	val := e.lastValue
	for _, key := range pointer {
		key = strings.Replace(key, "~1", "/", -1)
		key = strings.Replace(key, "~0", "~", -1)
		val = val.Get(key)
		if val == nil {
			return nil, ErrValueNotFound
		}
	}
	return val, nil
}

func (e *Extractor) readData() error {
	if e.evt == nil {
		return fmt.Errorf("event reader has not been set")
	}
	// Decode the json, but only if we haven't done it yet for this event
	if e.evt.EventNum() != e.lastEvtNum {
		reader := e.evt.Reader()

		// As a very quick sanity check, only try to extract all if
		// the first character is '{' or '['
		data := []byte{0}
		_, err := reader.Read(data)
		if err != nil {
			return err
		}
		if !(data[0] == '{' || data[0] == '[') {
			return fmt.Errorf("invalid json format: '%s'", string(data))
		}

		_, err = reader.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		e.lastData, err = ioutil.ReadAll(reader)
		if err != nil {
			return err
		}

		// Try to parse the data as json
		e.lastValue, err = e.parser.ParseBytes(e.lastData)
		if err != nil {
			return err
		}
		e.lastEvtNum = e.evt.EventNum()
	}

	return nil
}
