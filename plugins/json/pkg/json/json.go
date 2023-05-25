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

// /////////////////////////////////////////////////////////////////////////////
// This plugin is a general json parser. It can be used to extract arbitrary
// fields from a buffer containing json data.
// /////////////////////////////////////////////////////////////////////////////
package json

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	"github.com/valyala/fastjson"
)

const (
	PluginName        = "json"
	PluginDescription = "implements extracting arbitrary fields from inputs formatted as JSON"
	PluginContact     = "github.com/falcosecurity/plugins/"
	PluginVersion     = "0.7.0"
)

type Plugin struct {
	plugins.BasePlugin
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	Config      PluginConfig
}

func (m *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
	}
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		// all properties are optional by default
		RequiredFromJSONSchemaTags: true,
		// unrecognized properties don't cause a parsing failures
		AllowAdditionalProperties: true,
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (m *Plugin) Init(config string) error {
	// read configuration
	m.Config.Reset()
	json.Unmarshal([]byte(config), &m.Config)

	// setup optional async extraction optimization
	extract.SetAsync(m.Config.UseAsync)
	return nil
}

func (m *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{
			Type: "string",
			Name: "json.value",
			Arg:  sdk.FieldEntryArg{IsRequired: true, IsKey: true},
			Desc: "Extracts a value from a JSON-encoded input. Syntax is json.value[<json pointer>], where <json pointer> is a json pointer (see https://datatracker.ietf.org/doc/html/rfc6901)",
		},
		{
			Type: "string",
			Name: "json.obj",
			Desc: "The full json message as a text string.",
		},
		{
			Type: "string",
			Name: "json.rawtime",
			Desc: "The time of the event, identical to evt.rawtime.",
		},
		{
			Type: "string",
			Name: "jevt.value",
			Arg:  sdk.FieldEntryArg{IsRequired: true, IsKey: true},
			Desc: "Alias for json.value, provided for backwards compatibility.",
		},
		{
			Type: "string",
			Name: "jevt.obj",
			Desc: "Alias for json.obj, provided for backwards compatibility.",
		},
		{
			Type: "string",
			Name: "jevt.rawtime",
			Desc: "Alias for json.rawtime, provided for backwards compatibility.",
		},
	}
}

func (m *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	reader := evt.Reader()

	// As a very quick sanity check, only try to extract all if
	// the first character is '{' or '['
	data := []byte{0}
	_, err := reader.Read(data)
	if err != nil {
		return err
	}
	if !(data[0] == '{' || data[0] == '[') {
		return fmt.Errorf("invalid json format")
	}

	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != m.jdataEvtnum {
		_, err := reader.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		data, err = ioutil.ReadAll(reader)
		if err != nil {
			return err
		}

		// Try to parse the data as json
		m.jdata, err = m.jparser.ParseBytes(data)
		if err != nil {
			return err
		}
		m.jdataEvtnum = evt.EventNum()
	}

	switch req.FieldID() {
	case 3: // jevt.value
		fallthrough
	case 0: // json.value
		arg := req.ArgKey()
		if arg[0] == '/' {
			arg = arg[1:]
		}

		// walk the object using the json pointer syntax (RFC 6901)
		pointer := strings.Split(arg, "/")
		val := m.jdata
		for _, key := range pointer {
			key = strings.Replace(key, "~1", "/", -1)
			key = strings.Replace(key, "~0", "~", -1)
			val = val.Get(key)
			if val == nil {
				return nil
			}
		}

		if val.Type() == fastjson.TypeString {
			str, err := val.StringBytes()
			if err != nil {
				return err
			}
			req.SetValue(string(str))
		} else {
			req.SetValue(string(val.MarshalTo(nil)))
		}
	case 4: // jevt.obj
		fallthrough
	case 1: // json.obj
		// If we skipped the deserialization, we have to read
		// the event data.
		if len(data) == 1 {
			_, err := reader.Seek(0, io.SeekStart)
			if err != nil {
				return err
			}

			data, err = ioutil.ReadAll(reader)
			if err != nil {
				return err
			}
		}
		var out bytes.Buffer
		err = json.Indent(&out, data, "", "  ")
		if err != nil {
			return err
		}
		req.SetValue(out.String())
	case 5: // jevt.rawtime
		fallthrough
	case 2: // json.rawtime
		req.SetValue(fmt.Sprintf("%d", evt.Timestamp()))
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}
