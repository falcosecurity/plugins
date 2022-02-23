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
	"log"
	"math"
	"sync"

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
	"github.com/oschwald/maxminddb-golang"
	"github.com/valyala/fastjson"
)

// Plugin info
const (
	PluginRequiredApiVersion        = "0.2.0"
	PluginID                 uint32 = 2
	PluginName                      = "cloudtrail"
	PluginDescription               = "reads cloudtrail JSON data saved to file in the directory specified in the settings"
	PluginContact                   = "github.com/falcosecurity/plugins/"
	PluginVersion                   = "0.1.0"
	PluginEventSource               = "aws_cloudtrail"
)

const defaultS3DownloadConcurrency = 1
const verbose bool = false

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

// This is the global plugin state, identifying an instance of this plugin
type pluginContext struct {
	plugins.BasePlugin
	jparser               fastjson.Parser
	jdata                 *fastjson.Value
	jdataEvtnum           uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	sqsDelete             bool   // If true, will delete SQS Messages immediately after receiving them
	s3DownloadConcurrency int
	useAsync              bool
	geoipDB               *maxminddb.Reader // Used to resolve IPs to countries/cities
}

// Struct for plugin init config
type pluginInitConfig struct {
	S3DownloadConcurrency int  `json:"s3DownloadConcurrency"`
	SQSDelete             bool `json:"sqsDelete"`
	UseAsync              bool `json:"useAsync"`
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

func (p *pluginContext) Info() *plugins.Info {
	//log.Printf("[%s] Info\n", PluginName)
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

func (p *pluginContext) Init(cfg string) error {
	if !verbose {
		log.SetOutput(ioutil.Discard)
	}

	log.Printf("[%s] Init, config=%s\n", PluginName, cfg)

	p.jdataEvtnum = math.MaxUint64
	p.sqsDelete = true
	p.s3DownloadConcurrency = defaultS3DownloadConcurrency
	p.useAsync = false

	if cfg != "" {
		var initConfig pluginInitConfig
		initConfig.SQSDelete = true
		initConfig.S3DownloadConcurrency = defaultS3DownloadConcurrency
		initConfig.UseAsync = false

		err := json.Unmarshal([]byte(cfg), &initConfig)
		if err != nil {
			return err
		}

		p.sqsDelete = initConfig.SQSDelete
		p.s3DownloadConcurrency = initConfig.S3DownloadConcurrency
		p.useAsync = initConfig.UseAsync
	}

	if p.useAsync {
		extract.StartAsync(p)
	}

	// If available, load the maxmind geoip database that we will use to gather country/city info
	var err error
	p.geoipDB, err = maxminddb.Open("./GeoLite2-City.mmdb")
	if err != nil {
		p.geoipDB = nil
		log.Printf("[%s] Cannot load GeoLite2-City.mmdb, geoIP resolution will be disabled: %s\n", PluginName, err)
	}

	return nil
}

func (p *pluginContext) Destroy() {
	log.Printf("[%s] Destroy\n", PluginName)

	if p.useAsync {
		extract.StopAsync(p)
	}

	if p.geoipDB != nil {
		p.geoipDB.Close()
	}
}

func (p *pluginContext) Open(params string) (source.Instance, error) {
	log.Printf("[%s] Open, params=%s\n", PluginName, params)

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
	oCtx.s3.DownloadBufs = make([][]byte, p.s3DownloadConcurrency)

	return oCtx, nil
}

func (o *openContext) Close() {
	log.Printf("[%s] Close\n", PluginName)
}

func (o *openContext) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	log.Printf("[%s] NextBatch\n", PluginName)

	var n int
	var err error
	pCtx := pState.(*pluginContext)
	for n = 0; err == nil && n < evts.Len(); n++ {
		err = nextEvent(pCtx, o, evts.Get(n))
	}
	return n, err
}

func (o *openContext) Progress(pState sdk.PluginState) (float64, string) {
	log.Printf("[%s] Progress\n", PluginName)

	pd := float64(o.curFileNum) / float64(len(o.files))
	return pd, fmt.Sprintf("%.2f%% - %v/%v files", pd*100, o.curFileNum, len(o.files))
}

func (p *pluginContext) String(in io.ReadSeeker) (string, error) {
	log.Printf("[%s] String\n", PluginName)

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

	info := getEvtInfo(p, p.jdata)

	return fmt.Sprintf("%s%s %s %s %s",
		region,
		user,
		src,
		ename,
		info,
	), nil
}

func (p *pluginContext) Fields() []sdk.FieldEntry {
	//log.Printf("[%s] Fields\n", PluginName)

	return supportedFields
}

func (p *pluginContext) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {
	log.Printf("[%s] Extract\n", PluginName)

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
		present, value = getfieldStr(p, p.jdata, req.Field())
	}
	if present {
		req.SetValue(value)
	}

	return nil
}

func main() {}
