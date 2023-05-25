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
// This plugin reads reading cloudtrail files from a local directory or from a
// remote S3 bucket. Cloudtrail events are dispatched to the engine one by one,
// in their original json form, so the full data is retained.
// The plugin also exports a bunch of filter fields useful for cloudtrail
// analysis..
///////////////////////////////////////////////////////////////////////////////

package cloudtrail

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math"

	"github.com/alecthomas/jsonschema"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/progress"
	"github.com/valyala/fastjson"
)

// Plugin info
const (
	PluginID          uint32 = 2
	PluginName               = "cloudtrail"
	PluginDescription        = "reads cloudtrail JSON data saved to file in the directory specified in the settings"
	PluginContact            = "github.com/falcosecurity/plugins/"
	PluginVersion            = "0.8.0"
	PluginEventSource        = "aws_cloudtrail"
)

// This is the global plugin state, identifying an instance of this plugin
type Plugin struct {
	plugins.BasePlugin
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	Config      PluginConfig
	ConfigAWS   aws.Config
}

func (p *Plugin) Info() *plugins.Info {
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
	p.jdataEvtnum = math.MaxUint64

	// Set config default values and read the passed one, if available.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	p.Config.Reset()
	json.Unmarshal([]byte(cfg), &p.Config)

	// create an AWS config from the given plugin config
	awsCfg, err := p.Config.AWS.ConfigAWS()
	if err != nil {
		return err
	}
	p.ConfigAWS = awsCfg.Copy()

	// enable/disable async extraction optimazion (enabled by default)
	extract.SetAsync(p.Config.UseAsync)
	return nil
}

func (p *Plugin) Open(params string) (source.Instance, error) {
	// Allocate the context struct for this open instance
	oCtx := &PluginInstance{
		config:    p.Config,
		awsConfig: p.ConfigAWS.Copy(),
	}

	// Perform the open
	var err error
	if len(params) >= 5 && params[:5] == "s3://" {
		err = oCtx.openS3(params)
	} else if len(params) >= 6 && params[:6] == "sqs://" {
		err = oCtx.openSQS(params)
	} else {
		err = oCtx.openLocal(params)
	}

	if err != nil {
		return nil, err
	}

	return oCtx, nil
}

func (o *PluginInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	var n int
	var err error
	for n = 0; n < evts.Len(); n++ {
		err = o.nextEvent(evts.Get(n))
		if err != nil {
			break
		}
	}
	return n, err
}

func (o *PluginInstance) Progress(pState sdk.PluginState) (float64, string) {
	pd := float64(o.curFileNum) / float64(len(o.files))
	return pd, fmt.Sprintf("%.2f%% - %v/%v files", pd*100, o.curFileNum, len(o.files))
}

// todo: optimize this to cache by event number
func (p *Plugin) String(evt sdk.EventReader) (string, error) {
	var src string
	var user string
	var err error

	data, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return "", err
	}

	p.jdata, err = p.jparser.ParseBytes(data)
	if err != nil {
		return "", fmt.Errorf("<invalid JSON: %s>" + err.Error())
	}
	val := p.jdata.GetStringBytes("eventSource")
	if val == nil {
		return "", fmt.Errorf("<invalid JSON: event did not contain a source>")
	}

	src = string(val)

	val = p.jdata.GetStringBytes("awsRegion")
	if val == nil {
		return "", fmt.Errorf("<invalid JSON: event did not contain an awsRegion>")
	}

	region := string(val)

	val = p.jdata.GetStringBytes("eventName")
	if val == nil {
		return "", fmt.Errorf("<invalid JSON: event did not contain an eventName>")
	}

	ename := string(val)

	if len(src) > len(".amazonaws.com") {
		srctrailer := src[len(src)-len(".amazonaws.com"):]
		if srctrailer == ".amazonaws.com" {
			src = src[0 : len(src)-len(".amazonaws.com")]
		}
	}

	present, user := getUser(p.jdata)
	if present && user != "" {
		user = " " + user
	}

	info := getEvtInfo(p.jdata)

	return fmt.Sprintf("%s%s %s %s %s",
		region,
		user,
		src,
		ename,
		info,
	), nil
}

func (p *Plugin) Fields() []sdk.FieldEntry {
	return supportedFields
}

func (p *Plugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	// Decode the json, but only if we haven't done it yet for this event
	if evt.EventNum() != p.jdataEvtnum {
		// Read the event data
		data, err := ioutil.ReadAll(evt.Reader())
		if err != nil {
			return err
		}

		// Maybe temp--remove trailing null bytes from string
		data = bytes.Trim(data, "\x00")

		// For this plugin, events are always strings
		evtStr := string(data)

		p.jdata, err = p.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return err
		}
		p.jdataEvtnum = evt.EventNum()
	}

	// Extract the field value
	var present bool
	var value interface{}
	if req.FieldType() == sdk.FieldTypeUint64 {
		present, value = getfieldU64(p.jdata, req.Field())
	} else {
		present, value = getfieldStr(p.jdata, req.Field())
	}
	if present {
		req.SetValue(value)
	}

	return nil
}
