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

package dummy

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"strconv"
	"time"

	"github.com/alecthomas/jsonschema"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
)

const (
	PluginID          uint32 = 3
	PluginName               = "dummy"
	PluginDescription        = "Reference plugin for educational purposes"
	PluginContact            = "github.com/falcosecurity/plugins"
	PluginVersion            = "0.11.4"
	PluginEventSource        = "dummy"
)

type PluginConfig struct {
	// This reflects potential internal state for the plugin. In
	// this case, the plugin is configured with a jitter.
	Jitter uint64 `json:"jitter" jsonschema:"title=Sample jitter,description=A random amount added to the sample of each event (Default: 10),default=10"`
}

type PluginOpenParams struct {
	Start     uint64 `json:"start" jsonschema:"title=Start value,description=The starting value of the sample (Default: 1),default=1"`
	MaxEvents uint64 `json:"maxEvents" jsonschema:"title=Max num events,description=The number of events to return before returning EOF (Default: 20),default=20"`
}

type Plugin struct {
	plugins.BasePlugin
	// Will be used to randomize samples
	rand *rand.Rand
	// Contains the init configuration values
	config PluginConfig
	// Contains the open params configuration
	openParams PluginOpenParams
}

func (p *PluginConfig) setDefault() {
	p.Jitter = 10
}

func (p *PluginOpenParams) setDefault() {
	p.Start = 1
	p.MaxEvents = 20
}

func (m *Plugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:          PluginID,
		Name:        PluginName,
		Description: PluginDescription,
		Contact:     PluginContact,
		Version:     PluginVersion,
		EventSource: PluginEventSource,
	}
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&PluginConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (p *Plugin) Init(cfg string) error {
	// initialize state
	p.rand = rand.New(rand.NewSource(time.Now().UnixNano()))

	// The format of cfg is a json object with a single param
	// "jitter", e.g. {"jitter": 10}
	// Empty configs are allowed, in which case the default is used.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	p.config.setDefault()
	if len(cfg) != 0 {
		json.Unmarshal([]byte(cfg), &p.config)
	}
	return nil
}

func (p *Plugin) Destroy() {
	// nothing to do here
}

func (p *Plugin) Open(prms string) (source.Instance, error) {

	p.openParams.setDefault()
	if len(prms) != 0 {
		if err := json.Unmarshal([]byte(prms), &p.openParams); err != nil {
			return nil, fmt.Errorf("wrong open params format: %s", err.Error())
		}
	}

	evt_counter := uint64(0)
	sample := p.openParams.Start
	maxEvents := p.openParams.MaxEvents
	pull := func(ctx context.Context, evt sdk.EventWriter) error {
		if evt_counter >= uint64(maxEvents) {
			return sdk.ErrEOF
		}
		evt_counter++

		// Increment sample by 1, also add a jitter of [0:jitter]
		sample += 1 + uint64(p.rand.Int63n(int64(p.config.Jitter+1)))

		// The representation of a dummy event is the sample as a string.
		str := fmt.Sprintf("%d", sample)

		// It is not mandatory to set the Timestamp of the event (it
		// would be filled in by the framework if set to uint_max),
		// but it's a good practice.
		evt.SetTimestamp(uint64(time.Now().UnixNano()))

		_, err := evt.Writer().Write([]byte(str))
		return err
	}
	return source.NewPullInstance(pull)
}

// todo: optimize this to cache by event number
func (m *Plugin) String(evt sdk.EventReader) (string, error) {
	evtBytes, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	// The string representation of an event is a json object with the sample
	return fmt.Sprintf("{\"sample\": \"%s\"}", evtStr), nil
}

func (m *Plugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{
			Type: "uint64",
			Name: "dummy.divisible",
			Desc: "Return 1 if the value is divisible by the provided divisor, 0 otherwise",
			Arg:  sdk.FieldEntryArg{IsRequired: true, IsIndex: true},
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

func (m *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
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

		if !req.ArgPresent() {
			return fmt.Errorf("'dummy.divisible' field requires an argument, but no argument is provided")
		}

		divisor := req.ArgIndex()

		if uint64(evtVal)%divisor == 0 {
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
