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
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"strconv"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

// Plugin consts
const (
	PluginID          uint32 = 3
	PluginName               = "dummy"
	PluginDescription        = "Reference plugin for educational purposes"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.2.1"
	PluginEventSource        = "dummy"
)

///////////////////////////////////////////////////////////////////////////////

type MyPluginConfig struct {
	// This reflects potential internal state for the plugin. In
	// this case, the plugin is configured with a jitter.
	Jitter uint64 `json:"jitter" jsonschema:"description=A random amount added to the sample of each event (Default: 10)"`
}

type MyPlugin struct {
	plugins.BasePlugin
	// Will be used to randomize samples
	rand *rand.Rand
	// Contains the init configuration values
	config MyPluginConfig
}

type MyInstance struct {
	source.BaseInstance

	// Copy of the init params from plugin_open()
	initParams string

	// The number of events to return before EOF
	maxEvents uint64

	// A count of events returned. Used to count against maxEvents.
	counter uint64

	// A semi-random numeric value, derived from this value and
	// jitter. This is put in every event as the data property.
	sample uint64
}

func init() {
	p := &MyPlugin{}
	source.Register(p)
	extractor.Register(p)
}

func (p *MyPluginConfig) setDefault() {
	p.Jitter = 10
}

func (m *MyPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *MyPlugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&MyPluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (m *MyPlugin) Init(cfg string) error {
	// initialize state
	m.rand = rand.New(rand.NewSource(time.Now().UnixNano()))

	// The format of cfg is a json object with a single param
	// "jitter", e.g. {"jitter": 10}
	// Empty configs are allowed, in which case the default is used.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	m.config.setDefault()
	json.Unmarshal([]byte(cfg), &m.config)

	return nil
}

func (m *MyPlugin) Destroy() {
	// nothing to do here
}

func (m *MyPlugin) Open(prms string) (source.Instance, error) {
	// The format of params is a json object with two params:
	// - "start", which denotes the initial value of sample
	// - "maxEvents": which denotes the number of events to return before EOF.
	// Example:
	// {"start": 1, "maxEvents": 1000}
	var obj map[string]uint64
	err := json.Unmarshal([]byte(prms), &obj)
	if err != nil {
		return nil, fmt.Errorf("params %s could not be parsed: %v", prms, err)
	}
	if _, ok := obj["start"]; !ok {
		return nil, fmt.Errorf("params %s did not contain start property", prms)
	}

	if _, ok := obj["maxEvents"]; !ok {
		return nil, fmt.Errorf("params %s did not contain maxEvents property", prms)
	}

	return &MyInstance{
		initParams: prms,
		maxEvents:  obj["maxEvents"],
		counter:    0,
		sample:     obj["start"],
	}, nil
}

func (m *MyInstance) Close() {
	// nothing to do here
}

func (m *MyInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	// Return EOF if reached maxEvents
	if m.counter >= m.maxEvents {
		return 0, sdk.ErrEOF
	}

	var n int
	var evt sdk.EventWriter
	myPlugin := pState.(*MyPlugin)
	for n = 0; m.counter < m.maxEvents && n < evts.Len(); n++ {
		evt = evts.Get(n)
		m.counter++

		// Increment sample by 1, also add a jitter of [0:jitter]
		m.sample += 1 + uint64(myPlugin.rand.Int63n(int64(myPlugin.config.Jitter+1)))

		// The representation of a dummy event is the sample as a string.
		str := strconv.Itoa(int(m.sample))

		// It is not mandatory to set the Timestamp of the event (it
		// would be filled in by the framework if set to uint_max),
		// but it's a good practice.
		evt.SetTimestamp(uint64(time.Now().UnixNano()))

		_, err := evt.Writer().Write([]byte(str))
		if err != nil {
			return 0, err
		}
	}
	return n, nil
}

func (m *MyPlugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	// The string representation of an event is a json object with the sample
	return fmt.Sprintf("{\"sample\": \"%s\"}", evtStr), nil
}

func (m *MyPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{
			Type: "uint64",
			Name: "dummy.divisible",
			Desc: "Return 1 if the value is divisible by the provided divisor, 0 otherwise",
			Arg:  sdk.FieldEntryArg{IsRequired: true, IsKey: true},
		},
		{
			Type: "uint64",
			Name: "dummy.value",
			Desc: "The sample value in the event",
		},
		{
			Type: "string",
			Name: "dummy.strvalue",
			Desc: "The sample value in the event, as a string",
		},
	}
}

func (m *MyPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return err
	}
	evtStr := string(evtBytes)
	evtVal, err := strconv.Atoi(evtStr)
	if err != nil {
		return err
	}

	switch req.FieldID() {
	case 0: // dummy.divisible
		divisor, err := strconv.Atoi(req.ArgKey())
		if err != nil {
			return fmt.Errorf("argument to dummy.divisible %s could not be converted to number", req.ArgKey())
		}
		if evtVal%divisor == 0 {
			req.SetValue(uint64(1))
		} else {
			req.SetValue(uint64(0))
		}
	case 1: // dummy.value
		req.SetValue(uint64(evtVal))
	case 2: // dummy.strvalue
		req.SetValue(evtStr)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

func main() {}
