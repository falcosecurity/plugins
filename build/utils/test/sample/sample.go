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

package main

import (
	"encoding/gob"
	"errors"
	"fmt"
	"time"

	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

type Plugin struct {
	plugins.BasePlugin
}

type Instance struct {
	source.BaseInstance
	counter uint64
}

func init() {
	plugins.SetFactory(func() plugins.Plugin {
		p := &Plugin{}
		source.Register(p)
		extractor.Register(p)
		return p
	})
}

func (m *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                  999,
		Name:                "sample",
		Description:         "Sample",
		Contact:             "github.com/falcosecurity/plugins/",
		Version:             "0.0.1",
		EventSource:         "sample",
		RequiredAPIVersion:  "1.0.0",
		ExtractEventSources: []string{"sample", "sample2"},
	}
}

func (m *Plugin) InitSchema() *sdk.SchemaInfo {
	return &sdk.SchemaInfo{
		Schema: "test schema",
	}
}

func (m *Plugin) Init(config string) error {
	if config != "test config" {
		return errors.New("test init error")
	}
	return nil
}

func (m *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "uint64", Name: "sample.count", Display: "Counter value", Desc: "Current value of the internal counter"},
		{Type: "string", Name: "sample.countstr", Display: "Counter string value", Desc: "String represetation of current value of the internal counter"},
	}
}

func (m *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	var value uint64
	encoder := gob.NewDecoder(evt.Reader())
	if err := encoder.Decode(&value); err != nil {
		return err
	}
	switch req.FieldID() {
	case 0:
		req.SetValue(value)
		return nil
	case 1:
		req.SetValue(fmt.Sprintf("%d", value))
		return nil
	default:
		return fmt.Errorf("unsupported field: %s", req.Field())
	}
}

func (m *Plugin) OpenParams() ([]sdk.OpenParam, error) {
	return []sdk.OpenParam{
		{
			Value: "file:///hello-world.bin",
			Desc:  "A resource that can be opened by this plugin. This is not used here and just serves an example.",
		},
	}, nil
}

func (m *Plugin) Open(params string) (source.Instance, error) {
	return &Instance{
		counter: 0,
	}, nil
}

func (m *Plugin) String(evt sdk.EventReader) (string, error) {
	var value uint64
	encoder := gob.NewDecoder(evt.Reader())
	if err := encoder.Decode(&value); err != nil {
		return "", err
	}
	return fmt.Sprintf("counter: %d", value), nil
}

func (m *Instance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	var n int
	var evt sdk.EventWriter
	for n = 0; n < evts.Len(); n++ {
		evt = evts.Get(n)
		m.counter++
		encoder := gob.NewEncoder(evt.Writer())
		if err := encoder.Encode(m.counter); err != nil {
			return 0, err
		}
		evt.SetTimestamp(uint64(time.Now().UnixNano()))
	}
	return n, nil
}

func (m *Instance) Progress(pState sdk.PluginState) (float64, string) {
	return 1.0, "1.0"
}

func (m *Instance) Close() {

}

func (m *Plugin) Destroy() {

}

func main() {}
