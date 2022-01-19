/*
Copyright (C) 2021 The Falco Authors.

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
// analysis (see plugin_get_fields() for the list).
///////////////////////////////////////////////////////////////////////////////

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"sync"

	"github.com/alecthomas/jsonschema"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/extract"
	_ "github.com/falcosecurity/plugin-sdk-go/pkg/sdk/symbols/progress"
	"github.com/valyala/fastjson"
)

// Plugin info
const (
	PluginRequiredApiVersion        = "0.3.0"
	PluginID                 uint32 = 2
	PluginName                      = "cloudtrail"
	PluginDescription               = "reads cloudtrail JSON data saved to file in the directory specified in the settings"
	PluginContact                   = "github.com/falcosecurity/plugins/"
	PluginVersion                   = "0.2.1"
	PluginEventSource               = "aws_cloudtrail"
)

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

type fileInfo struct {
	name         string
	isCompressed bool
}

// This is the state that we use when reading events from an S3 bucket
type s3State struct {
	bucket                string
	awsSvc                *s3.S3
	awsSess               *session.Session
	downloader            *s3manager.Downloader
	DownloadWg            sync.WaitGroup
	DownloadBufs          [][]byte
	lastDownloadedFileNum int
	nFilledBufs           int
	curBuf                int
}

type snsMessage struct {
	Bucket string   `json:"s3Bucket"`
	Keys   []string `json:"s3ObjectKey"`
}

// Struct for plugin init config
type pluginInitConfig struct {
	S3DownloadConcurrency int  `json:"s3DownloadConcurrency" jsonschema:"description=Controls the number of background goroutines used to download S3 files (Default: 1)"`
	SQSDelete             bool `json:"sqsDelete" jsonschema:"description=If true then the plugin will delete sqs messages from the queue immediately after receiving them (Default: true)"`
	UseAsync              bool `json:"useAsync" jsonschema:"description=If true then async extraction optimization is enabled (Default: true)"`
}

// This is the global plugin state, identifying an instance of this plugin
type pluginContext struct {
	plugins.BasePlugin
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	config      pluginInitConfig
}

type OpenMode int

const (
	fileMode OpenMode = iota
	s3Mode
	sqsMode
)

// This is the open state, identifying an open instance reading cloudtrail files from
// a local directory or from a remote S3 bucket (either direct or via a SQS queue)
type openContext struct {
	source.BaseInstance
	openMode           OpenMode
	cloudTrailFilesDir string
	files              []fileInfo
	curFileNum         uint32
	evtJSONStrings     [][]byte
	evtJSONListPos     int
	s3                 s3State
	sqsClient          *sqs.Client
	queueURL           string
	nextJParser        fastjson.Parser
}

// Register the plugin
func init() {
	p := &pluginContext{}
	source.Register(p)
	extractor.Register(p)
}

func (p *pluginInitConfig) setDefault() {
	p.SQSDelete = true
	p.S3DownloadConcurrency = 1
	p.UseAsync = true
}

func (p *pluginContext) Info() *plugins.Info {
	return &plugins.Info{
		ID:                  PluginID,
		Name:                PluginName,
		Description:         PluginDescription,
		Contact:             PluginContact,
		Version:             PluginVersion,
		RequiredAPIVersion:  PluginRequiredApiVersion,
		EventSource:         PluginEventSource,
		ExtractEventSources: []string{"ct", "s3", "ec2"},
	}
}

func (p *pluginContext) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&pluginInitConfig{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (p *pluginContext) Init(cfg string) error {
	// initialize state
	p.jdataEvtnum = math.MaxUint64

	// Set config default values and read the passed one, if available.
	// Since we provide a schema through InitSchema(), the framework
	// guarantees that the config is always well-formed json.
	p.config.setDefault()
	json.Unmarshal([]byte(cfg), &p.config)

	// enable/disable async extraction optimazion (enabled by default)
	extract.SetAsync(p.config.UseAsync)
	return nil
}

func (p *pluginContext) Open(params string) (source.Instance, error) {
	// Allocate the context struct for this open instance
	oCtx := &openContext{}

	// Perform the open
	var err error
	if len(params) >= 5 && params[:5] == "s3://" {
		err = openS3(p, oCtx, params)
	} else if len(params) >= 6 && params[:6] == "sqs://" {
		err = openSQS(p, oCtx, params)
	} else {
		err = openLocal(p, oCtx, params)
	}

	if err != nil {
		return nil, err
	}

	// Create an array of download buffers that will be used to concurrently
	// download files from s3
	oCtx.s3.DownloadBufs = make([][]byte, p.config.S3DownloadConcurrency)

	return oCtx, nil
}

func (o *openContext) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	var n int
	var err error
	pCtx := pState.(*pluginContext)
	for n = 0; err == nil && n < evts.Len(); n++ {
		err = nextEvent(pCtx, o, evts.Get(n))
	}
	return n, err
}

func (o *openContext) Progress(pState sdk.PluginState) (float64, string) {
	pd := float64(o.curFileNum) / float64(len(o.files))
	return pd, fmt.Sprintf("%.2f%% - %v/%v files", pd*100, o.curFileNum, len(o.files))
}

func (p *pluginContext) String(in io.ReadSeeker) (string, error) {
	var src string
	var user string
	var err error

	data, err := ioutil.ReadAll(in)
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

func (p *pluginContext) Fields() []sdk.FieldEntry {
	return supportedFields
}

func (p *pluginContext) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
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
	if req.FieldType() == sdk.ParamTypeUint64 {
		present, value = getfieldU64(p.jdata, req.Field())
	} else {
		present, value = getfieldStr(p.jdata, req.Field())
	}
	if present {
		req.SetValue(value)
	}

	return nil
}

func main() {}
