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

///////////////////////////////////////////////////////////////////////////////
// This plugin is a general json parser. It can be used to extract arbitrary
// fields from a buffer containing json data.
///////////////////////////////////////////////////////////////////////////////
package main

import (
	"fmt"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugins/plugins/json/pkg/json"
)

// Plugin info
const (
	PluginRequiredApiVersion = "0.3.0"
	PluginName               = "json"
	PluginDescription        = "implements extracting arbitrary fields from inputs formatted as JSON"
	PluginContact            = "github.com/falcosecurity/plugins/"
	PluginVersion            = "0.2.2"
)

type MyPlugin struct {
	plugins.BasePlugin
	helper json.Extractor
}

func init() {
	p := &MyPlugin{}
	extractor.Register(p)
}

func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		Name:               PluginName,
		Description:        PluginDescription,
		Contact:            PluginContact,
		Version:            PluginVersion,
		RequiredAPIVersion: PluginRequiredApiVersion,
	}
}

func (m *MyPlugin) Init(config string) error {
	return nil
}

func (m *MyPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "json.value", ArgRequired: true, Desc: "Extracts a value from a JSON-encoded input. Syntax is json.value[<json pointer>], where <json pointer> is a json pointer (see https://datatracker.ietf.org/doc/html/rfc6901)"},
		{Type: "string", Name: "json.obj", Desc: "The full json message as a text string."},
		{Type: "string", Name: "json.rawtime", Desc: "The time of the event, identical to evt.rawtime."},
		{Type: "string", Name: "jevt.value", ArgRequired: true, Desc: "Alias for json.value, provided for backwards compatibility."},
		{Type: "string", Name: "jevt.obj", Desc: "Alias for json.obj, provided for backwards compatibility."},
		{Type: "string", Name: "jevt.rawtime", Desc: "Alias for json.rawtime, provided for backwards compatibility."},
	}
}

func (m *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	switch req.FieldID() {
	case 3: // jevt.value
		fallthrough
	case 0: // json.value
		m.helper.SetEventReader(evt)
		return m.helper.ExtractValue(req, req.Arg())
	case 4: // jevt.obj
		fallthrough
	case 1: // json.obj
		m.helper.SetEventReader(evt)
		return m.helper.ExtractObject(req)
	case 5: // jevt.rawtime
		fallthrough
	case 2: // json.rawtime
		req.SetValue(fmt.Sprintf("%d", evt.Timestamp()))
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

func main() {
}
