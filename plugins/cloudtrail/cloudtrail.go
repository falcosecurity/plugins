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

// #cgo CFLAGS: -I${SRCDIR}/../../
/*
#include <plugin_info.h>
*/
import "C"
import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/falcosecurity/plugin-sdk-go"
	"github.com/falcosecurity/plugin-sdk-go/state"
	"github.com/falcosecurity/plugin-sdk-go/wrappers"
	"github.com/valyala/fastjson"
)

// Plugin info
const (
	PluginRequiredApiVersion = "1.0.0"
	PluginID          uint32 = 2
	PluginName               = "cloudtrail"
	PluginFilterName         = "ct"
	PluginDescription        = "reads cloudtrail JSON data saved to file in the directory specified in the settings"
	PluginContact            = "github.com/leogr/plugins/"
	PluginVersion = "0.0.1"
	PluginEventSource        = "aws_cloudtrail"
)

const defaultS3DownloadConcurrency = 1
const verbose bool = true
const outBufSize uint32 = 65535

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

///////////////////////////////////////////////////////////////////////////////
// PLUGIN STATE STRUCTS
///////////////////////////////////////////////////////////////////////////////

// This is the global plugin state, identifying an instance of this plugin
type pluginContext struct {
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	lastError   error
	sqsDelete   bool   // If true, will delete SQS Messages immediately after receiving them
	s3DownloadConcurrency int
}

// Struct for plugin init config
type pluginInitConfig struct {
	S3DownloadConcurrency     int        `json:"s3DownloadConcurrency"`
	SQSDelete                 bool       `json:"sqsDelete"`
}

type OpenMode int

const (
	fileMode    OpenMode = iota
	s3Mode
	sqsMode
)

// This is the open state, identifying an open instance reading cloudtrail files from
// a local directory or from a remote S3 bucket (either direct or via a SQS queue)
type openContext struct {
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

///////////////////////////////////////////////////////////////////////////////
// PLUGIN INTERFACE IMPLEMENTATION
///////////////////////////////////////////////////////////////////////////////

//export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	return C.CString(PluginRequiredApiVersion)
}

//export plugin_get_type
func plugin_get_type() uint32 {
	return sdk.TypeSourcePlugin
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
	if !verbose {
		log.SetOutput(ioutil.Discard)
	}

	cfg := C.GoString(config)

	log.Printf("[%s] plugin_init\n", PluginName)
	log.Printf("config string:\n%s\n", cfg)

	// Allocate the context struct attach it to the state
	pCtx := &pluginContext{
		jdataEvtnum: math.MaxUint64,
		sqsDelete:   true,
	}

	if cfg != "" {
		var initConfig pluginInitConfig
		initConfig.SQSDelete = true
		initConfig.S3DownloadConcurrency = defaultS3DownloadConcurrency

		err := json.Unmarshal([]byte(cfg), &initConfig)
		if err != nil {
			pCtx.lastError = err
			*rc = sdk.SSPluginFailure
			return nil
		}
		pCtx.sqsDelete = initConfig.SQSDelete
		pCtx.s3DownloadConcurrency = initConfig.S3DownloadConcurrency
	}

	// Allocate the container for buffers and context
	pluginState := state.NewStateContainer()

	state.SetContext(pluginState, unsafe.Pointer(pCtx))

	*rc = sdk.SSPluginSuccess
	return pluginState
}

//export plugin_get_last_error
func plugin_get_last_error(plgState unsafe.Pointer) *C.char {
	pCtx := (*pluginContext)(state.Context(plgState))
	if pCtx.lastError != nil {
		return C.CString(pCtx.lastError.Error())
	}

	return C.CString("no error")
}

//export plugin_destroy
func plugin_destroy(plgState unsafe.Pointer) {
	log.Printf("[%s] plugin_destroy\n", PluginName)
	state.Free(plgState)
}

//export plugin_get_id
func plugin_get_id() uint32 {
	return PluginID
}

//export plugin_get_name
func plugin_get_name() *C.char {
	return C.CString(PluginName)
}

//export plugin_get_filter_name
func plugin_get_filter_name() *C.char {
	return C.CString(PluginFilterName)
}

//export plugin_get_version
func plugin_get_version() *C.char {
	return C.CString(PluginVersion)
}

//export plugin_get_description
func plugin_get_description() *C.char {
	return C.CString(PluginDescription)
}

//export plugin_get_contact
func plugin_get_contact() *C.char {
	return C.CString(PluginContact)
}

//export plugin_get_event_source
func plugin_get_event_source() *C.char {
	return C.CString(PluginEventSource)
}

//export plugin_get_fields
func plugin_get_fields() *C.char {
	flds := []sdk.FieldEntry{
		{Type: "string", Name: "ct.id", Display: "Event ID", Desc: "the unique ID of the cloudtrail event (eventID in the json)."},
		{Type: "string", Name: "ct.error", Display: "Error Code", Desc: "The error code from the event. Will be \"\" if there was no error."},
		{Type: "string", Name: "ct.time", Display: "Timestamp", Desc: "the timestamp of the cloudtrail event (eventTime in the json).", Properties: "hidden"},
		{Type: "string", Name: "ct.src", Display: "AWS Service", Desc: "the source of the cloudtrail event (eventSource in the json, without the '.amazonaws.com' trailer)."},
		{Type: "string", Name: "ct.name", Display: "Event Name", Desc: "the name of the cloudtrail event (eventName in the json)."},
		{Type: "string", Name: "ct.user", Display: "User Name", Desc: "the user of the cloudtrail event (userIdentity.userName in the json).", Properties: "conversation"},
		{Type: "string", Name: "ct.region", Display: "Region", Desc: "the region of the cloudtrail event (awsRegion in the json)."},
		{Type: "string", Name: "ct.srcip", Display: "Source IP", Desc: "the IP address generating the event (sourceIPAddress in the json).", Properties: "conversation"},
		{Type: "string", Name: "ct.useragent", Display: "User Agent", Desc: "the user agent generating the event (userAgent in the json)."},
		{Type: "string", Name: "ct.info", Display: "Info", Desc: "summary information about the event. This varies depending on the event type and, for some events, it contains event-specific details.", Properties: "info"},
		{Type: "string", Name: "ct.readonly", Display: "Read Only", Desc: "'true' if the event only reads information (e.g. DescribeInstances), 'false' if the event modifies the state (e.g. RunInstances, CreateLoadBalancer...)."},
		{Type: "string", Name: "s3.uri", Display: "Key URI", Desc: "the s3 URI (s3://<bucket>/<key>).", Properties: "conversation"},
		{Type: "string", Name: "s3.bucket", Display: "Bucket Name", Desc: "the bucket name for s3 events.", Properties: "conversation"},
		{Type: "string", Name: "s3.key", Display: "Key Name", Desc: "the S3 key name."},
		{Type: "string", Name: "s3.host", Display: "Host Name", Desc: "the S3 host name."},
		{Type: "uint64", Name: "s3.bytes", Display: "Tot Bytes", Desc: "the size of an s3 download or upload, in bytes."},
		{Type: "uint64", Name: "s3.bytes.in", Display: "Bytes In", Desc: "the size of an s3 upload, in bytes.", Properties: "hidden"},
		{Type: "uint64", Name: "s3.bytes.out", Display: "Bytes Out", Desc: "the size of an s3 download, in bytes.", Properties: "hidden"},
		{Type: "uint64", Name: "s3.cnt.get", Display: "N Get Ops", Desc: "the number of get operations. This field is 1 for GetObject events, 0 otherwise.", Properties: "hidden"},
		{Type: "uint64", Name: "s3.cnt.put", Display: "N Put Ops", Desc: "the number of put operations. This field is 1 for PutObject events, 0 otherwise.", Properties: "hidden"},
		{Type: "uint64", Name: "s3.cnt.other", Display: "N Other Ops", Desc: "the number of non I/O operations. This field is 0 for GetObject and PutObject events, 1 for all the other events.", Properties: "hidden"},
		{Type: "string", Name: "ec2.name", Display: "Instance Name", Desc: "the name of the ec2 instances, typically stored in the instance tags."},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		panic(err)
		return nil
	}

	return C.CString(string(b))
}

func dirExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	return false
}

func openLocal(pCtx *pluginContext, oCtx *openContext, params *C.char, rc *int32) {
	*rc = sdk.SSPluginFailure

	oCtx.openMode = fileMode

	oCtx.cloudTrailFilesDir = C.GoString(params)

	if len(oCtx.cloudTrailFilesDir) == 0 {
		pCtx.lastError = fmt.Errorf(PluginName + " plugin error: missing input directory argument")
		return
	}

	if !dirExists(oCtx.cloudTrailFilesDir) {
		pCtx.lastError = fmt.Errorf(PluginName+" plugin error: cannot open %s", oCtx.cloudTrailFilesDir)
		return
	}

	log.Printf("[%s] scanning directory %s\n", PluginName, oCtx.cloudTrailFilesDir)

	err := filepath.Walk(oCtx.cloudTrailFilesDir, func(path string, info os.FileInfo, err error) error {
		if info != nil && info.IsDir() {
			return nil
		}

		isCompressed := strings.HasSuffix(path, ".json.gz")
		if filepath.Ext(path) != ".json" && !isCompressed {
			return nil
		}

		var fi fileInfo = fileInfo{name: path, isCompressed: isCompressed}
		oCtx.files = append(oCtx.files, fi)
		return nil
	})
	if err != nil {
		pCtx.lastError = err
	}
	if len(oCtx.files) == 0 {
		pCtx.lastError = fmt.Errorf(PluginName + " plugin error: no json files found in " + oCtx.cloudTrailFilesDir)
		return
	}

	log.Printf("[%s] found %d json files\n", PluginName, len(oCtx.files))
	*rc = sdk.SSPluginSuccess
}

func initS3(oCtx *openContext) {
	oCtx.s3.awsSess = session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	oCtx.s3.awsSvc = s3.New(oCtx.s3.awsSess)

	oCtx.s3.downloader = s3manager.NewDownloader(oCtx.s3.awsSess)
}

func openS3(pCtx *pluginContext, oCtx *openContext, params *C.char, rc *int32) {
	*rc = sdk.SSPluginFailure
	input := C.GoString(params)

	oCtx.openMode = s3Mode

	// remove the initial "s3://"
	input = input[5:]
	slashindex := strings.Index(input, "/")

	// Extract the URL components
	var prefix string
	if slashindex == -1 {
		oCtx.s3.bucket = input
		prefix = ""
	} else {
		oCtx.s3.bucket = input[:slashindex]
		prefix = input[slashindex+1:]
	}

	initS3(oCtx)

	// Fetch the list of keys

	err := oCtx.s3.awsSvc.ListObjectsPages(&s3.ListObjectsInput{
		Bucket: &oCtx.s3.bucket,
		Prefix: &prefix,
	}, func(p *s3.ListObjectsOutput, last bool) (shouldContinue bool) {
		for _, obj := range p.Contents {
			//fmt.Printf("> %v %v\n", *obj.Size, *obj.Key)
			path := obj.Key
			isCompressed := strings.HasSuffix(*path, ".json.gz")
			if filepath.Ext(*path) != ".json" && !isCompressed {
				continue
			}

			var fi fileInfo = fileInfo{name: *path, isCompressed: true}
			oCtx.files = append(oCtx.files, fi)
		}
		return true
	})
	if err != nil {
		pCtx.lastError = fmt.Errorf(PluginName + " plugin error: failed to list objects: " + err.Error())
		*rc = sdk.SSPluginFailure
		return
	}

	*rc = sdk.SSPluginSuccess
}

func getMoreSQSFiles(pCtx *pluginContext, oCtx *openContext) error {
	ctx := context.Background()

	input := &sqs.ReceiveMessageInput{
		MessageAttributeNames: []string{
			string(types.QueueAttributeNameAll),
		},
		QueueUrl:            &oCtx.queueURL,
		MaxNumberOfMessages: 1,
	}

	msgResult, err := oCtx.sqsClient.ReceiveMessage(ctx, input)

	if err != nil {
		return err
	}

	if (len(msgResult.Messages) == 0) {
		return nil
	}

	if pCtx.sqsDelete {
		// Delete the message from the queue so it won't be read again
		delInput := &sqs.DeleteMessageInput{
			QueueUrl:      &oCtx.queueURL,
			ReceiptHandle: msgResult.Messages[0].ReceiptHandle,
		}

		_, err = oCtx.sqsClient.DeleteMessage(ctx, delInput)

		if err != nil {
			return err
		}
	}

	// The SQS message is just a SNS notification noting that new
	// cloudtrail file(s) are available in the s3 bucket. Download
	// those files.

	var sqsMsg map[string]interface{}

	err = json.Unmarshal([]byte(*msgResult.Messages[0].Body), &sqsMsg)

	if err != nil {
		return err
	}

	messageType, ok := sqsMsg["Type"]
	if !ok {
		return fmt.Errorf("Received SQS message that did not have a Type property")
	}

	if messageType.(string) != "Notification" {
		return fmt.Errorf("Received SQS message that was not a SNS Notification")
	}

	var notification snsMessage

	err = json.Unmarshal([]byte(sqsMsg["Message"].(string)), &notification)

	if err != nil {
		return err
	}

	// The notification contains a bucket and a list of keys that
	// contain new cloudtrail files.
	oCtx.s3.bucket = notification.Bucket

	initS3(oCtx)

	for _, key := range notification.Keys {

		isCompressed := strings.HasSuffix(key, ".json.gz")

		oCtx.files = append(oCtx.files, fileInfo{name: key, isCompressed: isCompressed})
	}

	return nil
}

func openSQS(pCtx *pluginContext, oCtx *openContext, params *C.char, rc *int32) {

	ctx := context.Background()
	input := C.GoString(params)

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		pCtx.lastError = err
		*rc = sdk.SSPluginFailure
		return
	}

	oCtx.openMode = sqsMode

	oCtx.sqsClient = sqs.NewFromConfig(cfg)

	queueName := input[6:]

	urlResult, err := oCtx.sqsClient.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{QueueName: &queueName})

	if err != nil {
		pCtx.lastError = err
		*rc = sdk.SSPluginFailure
		return
	}

	oCtx.queueURL = *urlResult.QueueUrl

	err = getMoreSQSFiles(pCtx, oCtx)

	if err != nil {
		pCtx.lastError = err
		*rc = sdk.SSPluginFailure
		return
	}

	*rc = sdk.SSPluginSuccess
}

//export plugin_open
func plugin_open(plgState unsafe.Pointer, params *C.char, rc *int32) unsafe.Pointer {
	pCtx := (*pluginContext)(state.Context(plgState))

	// Allocate the context struct for this open instance
	oCtx := &openContext{}

	// Perform the open
	input := C.GoString(params)
	if len(input) >= 5 && input[:5] == "s3://" {
		openS3(pCtx, oCtx, params, rc)
	} else if (len(input) >= 6 && input[:6] == "sqs://") {
		openSQS(pCtx, oCtx, params, rc)
	} else {
		openLocal(pCtx, oCtx, params, rc)
	}

	if *rc != sdk.SSPluginSuccess {
		return nil
	}

	// Allocate the library-compatible container for the open context
	openState := state.NewStateContainer()

	// Create an array of download buffers that will be used to concurrently
	// download files from s3
	oCtx.s3.DownloadBufs = make([][]byte, pCtx.s3DownloadConcurrency)

	// Tie the just created state to the open context
	//
	state.SetContext(openState, unsafe.Pointer(oCtx))

	// Allocate buffer for next()
	return openState
}

//export plugin_close
func plugin_close(plgState unsafe.Pointer, openState unsafe.Pointer) {
	if openState != nil {
		state.Free(openState)
	}
}

var dlErrChan chan error

func s3Download(oCtx *openContext, downloader *s3manager.Downloader, name string, dloadSlotNum int) {
	defer oCtx.s3.DownloadWg.Done()

	buff := &aws.WriteAtBuffer{}
	_, err := downloader.Download(buff,
		&s3.GetObjectInput{
			Bucket: &oCtx.s3.bucket,
			Key:    &name,
		})
	if err != nil {
		dlErrChan <- err
		return
	}

	oCtx.s3.DownloadBufs[dloadSlotNum] = buff.Bytes()
}

func readNextFileS3(pCtx *pluginContext, oCtx *openContext) ([]byte, error) {
	if oCtx.s3.curBuf < oCtx.s3.nFilledBufs {
		curBuf := oCtx.s3.curBuf
		oCtx.s3.curBuf++
		return oCtx.s3.DownloadBufs[curBuf], nil
	}

	dlErrChan = make(chan error, pCtx.s3DownloadConcurrency)
	k := oCtx.s3.lastDownloadedFileNum
	oCtx.s3.nFilledBufs = min(pCtx.s3DownloadConcurrency, len(oCtx.files)-k)
	for j, f := range oCtx.files[k : k+oCtx.s3.nFilledBufs] {
		oCtx.s3.DownloadWg.Add(1)
		go s3Download(oCtx, oCtx.s3.downloader, f.name, j)
	}
	oCtx.s3.DownloadWg.Wait()

	select {
	case e := <-dlErrChan:
		return nil, e
	default:
	}

	oCtx.s3.lastDownloadedFileNum += oCtx.s3.nFilledBufs

	oCtx.s3.curBuf = 1
	return oCtx.s3.DownloadBufs[0], nil
}

func readFileLocal(fileName string) ([]byte, error) {
	return ioutil.ReadFile(fileName)
}

func extractRecordStrings(jsonStr []byte, res *[][]byte) {
	indentation := 0
	var entryStart int

	for pos, char := range jsonStr {
		if char == '{' {
			if indentation == 1 {
				entryStart = pos
			}
			indentation++
		} else if char == '}' {
			indentation--
			if indentation == 1 {
				if pos < len(jsonStr)-1 {
					entry := jsonStr[entryStart : pos+1]
					*res = append(*res, entry)
				}
			}
		}
	}
}

// Next is the core event production function. It is called by both plugin_next() and plugin_next_batch()
func Next(plgState unsafe.Pointer, openState unsafe.Pointer) (*sdk.PluginEvent, int32) {
	var tmpStr []byte
	var err error

	pCtx := (*pluginContext)(state.Context(plgState))
	oCtx := (*openContext)(state.Context(openState))

	ret := sdk.PluginEvent{}

	// Only open the next file once we're sure that the content of the previous one has been full consumed
	if oCtx.evtJSONListPos == len(oCtx.evtJSONStrings) {
		// Open the next file and bring its content into memeory
		if oCtx.curFileNum >= uint32(len(oCtx.files)) {

			// If reading file names from a queue, try to
			// get more files first. Otherwise, return EOF.
			if oCtx.openMode == sqsMode {
				err = getMoreSQSFiles(pCtx, oCtx)
				if err != nil {
					return nil, sdk.SSPluginFailure
				}

				// If after trying, there are no
				// additional files, return timeout.
				if oCtx.curFileNum >= uint32(len(oCtx.files)) {
					return nil, sdk.SSPluginTimeout
				}
			} else {
				return nil, sdk.SSPluginEOF
			}
		}

		file := oCtx.files[oCtx.curFileNum]
		oCtx.curFileNum++

		switch (oCtx.openMode) {
		case s3Mode, sqsMode:
			tmpStr, err = readNextFileS3(pCtx, oCtx)
		case fileMode:
			tmpStr, err = readFileLocal(file.name)
		}
		if err != nil {
			pCtx.lastError = err
			return nil, sdk.SSPluginFailure
		}

		// The file can be gzipped. If it is, we unzip it.
		if file.isCompressed {
			gr, err := gzip.NewReader(bytes.NewBuffer(tmpStr))
			defer gr.Close()
			zdata, err := ioutil.ReadAll(gr)
			if err != nil {
				return nil, sdk.SSPluginTimeout
			}
			tmpStr = zdata
		}

		// Cloudtrail files have the following format:
		// {"Records":[
		//	{<evt1>},
		//	{<evt2>},
		//	...
		// ]}
		// Here, we split the file content into substrings, one per event.
		// We do this instead of unmarshaling the whole file because this allows
		// us to pass the original json of each event to the engine without an
		// additional marshaling, making things much faster.
		oCtx.evtJSONStrings = nil
		extractRecordStrings(tmpStr, &(oCtx.evtJSONStrings))

		oCtx.evtJSONListPos = 0
	}

	// Extract the next record
	var cr *fastjson.Value
	if len(oCtx.evtJSONStrings) != 0 {
		ret.Data = oCtx.evtJSONStrings[oCtx.evtJSONListPos]
		cr, err = oCtx.nextJParser.Parse(string(ret.Data))
		if err != nil {
			// Not json? Just skip this event.
			oCtx.evtJSONListPos++
			return nil, sdk.SSPluginTimeout
		}

		oCtx.evtJSONListPos++
	} else {
		// Json not int the expected format. Just skip this event.
		oCtx.evtJSONListPos++
		return nil, sdk.SSPluginTimeout
	}

	// Extract the timestamp
	t1, err := time.Parse(
		time.RFC3339,
		string(cr.GetStringBytes("eventTime")))
	if err != nil {
		//
		// We assume this is just some spurious data and we continue
		//
		return nil, sdk.SSPluginTimeout
	}
	ret.Timestamp = uint64(t1.Unix()) * 1000000000

	ets := string(cr.GetStringBytes("eventType"))
	if ets == "AwsCloudTrailInsight" {
		return nil, sdk.SSPluginTimeout
	}

	// Make sure the event is not too big for the engine
	if len(ret.Data) > int(sdk.MaxEvtSize) {
		pCtx.lastError = fmt.Errorf("cloudwatch message too long: %d, max %d supported", len(ret.Data), sdk.MaxEvtSize)
		return nil, sdk.SSPluginFailure
	}

	return &ret, sdk.SSPluginSuccess
}

//export plugin_next
func plugin_next(plgState unsafe.Pointer, openState unsafe.Pointer, retEvt **C.ss_plugin_event) int32 {
	evt, res := Next(plgState, openState)
	if res == sdk.SSPluginSuccess {
		*retEvt = (*C.ss_plugin_event)(wrappers.Events([]*sdk.PluginEvent{evt}))
	}

	log.Printf("[%s] plugin_next\n", PluginName)

	return res
}

//export plugin_get_progress
func plugin_get_progress(plgState unsafe.Pointer, openState unsafe.Pointer, progress_pct *uint32) *C.char {
	oCtx := (*openContext)(state.Context(openState))

	var pd float64 = float64(oCtx.curFileNum) * 100 / float64(len(oCtx.files))
	*progress_pct = oCtx.curFileNum * 10000 / uint32(len(oCtx.files))
	return C.CString(fmt.Sprintf("%.2f%% - %v/%v files", pd, oCtx.curFileNum, len(oCtx.files)))
}

func getUser(jdata *fastjson.Value) string {
	jutype := jdata.GetStringBytes("userIdentity", "type")
	if jutype != nil {
		utype := string(jutype)

		switch utype {
		case "Root", "IAMUser":
			jun := jdata.GetStringBytes("userIdentity", "userName")
			if jun != nil {
				return string(jun)
			}
		case "AWSService":
			jun := jdata.GetStringBytes("userIdentity", "invokedBy")
			if jun != nil {
				return string(jun)
			}
		case "AssumedRole":
			jun := jdata.GetStringBytes("userIdentity", "sessionContext", "sessionIssuer", "userName")
			if jun != nil {
				return string(jun)
			}
			return "AssumedRole"
		case "AWSAccount":
			return "AWSAccount"
		case "FederatedUser":
			return "FederatedUser"
		default:
			return "<unknown user type>"
		}
	}

	return "<NA>"
}

func getEvtInfo(jdata *fastjson.Value) string {
	var present bool
	var evtname string
	var info string
	var separator string

	present, evtname = getfieldStr(jdata, "ct.name")
	if !present {
		return "<invalid cloudtrail event: eventName field missing>"
	}

	switch evtname {
	case "PutBucketPublicAccessBlock":
		info = ""
		jpac := jdata.GetObject("requestParameters", "PublicAccessBlockConfiguration")
		if jpac != nil {
			info += fmt.Sprintf("BlockPublicAcls=%v BlockPublicPolicy=%v IgnorePublicAcls=%v RestrictPublicBuckets=%v ",
				jdata.GetBool("BlockPublicAcls"),
				jdata.GetBool("BlockPublicPolicy"),
				jdata.GetBool("IgnorePublicAcls"),
				jdata.GetBool("RestrictPublicBuckets"),
			)
		}
		return info
	default:
	}

	present, u64val := getfieldU64(jdata, "s3.bytes")
	if present {
		info = fmt.Sprintf("Size=%v", u64val)
		separator = " "
	}

	present, val := getfieldStr(jdata, "s3.uri")
	if present {
		info += fmt.Sprintf("%sURI=%s", separator, val)
		return info
	}

	present, val = getfieldStr(jdata, "s3.bucket")
	if present {
		info += fmt.Sprintf("%sBucket=%s", separator, val)
		return info
	}

	present, val = getfieldStr(jdata, "s3.key")
	if present {
		info += fmt.Sprintf("%sKey=%s", separator, val)
		return info
	}

	present, val = getfieldStr(jdata, "s3.host")
	if present {
		info += fmt.Sprintf("%sHost=%s", separator, val)
		return info
	}

	return info
}

func getfieldStr(jdata *fastjson.Value, field string) (bool, string) {
	var res string

	switch field {
	case "ct.id":
		res = string(jdata.GetStringBytes("eventID"))
	case "ct.error":
		res = string(jdata.GetStringBytes("errorCode"))
	case "ct.time":
		res = string(jdata.GetStringBytes("eventTime"))
	case "ct.src":
		res = string(jdata.GetStringBytes("eventSource"))

		if len(res) > len(".amazonaws.com") {
			srctrailer := res[len(res)-len(".amazonaws.com"):]
			if srctrailer == ".amazonaws.com" {
				res = res[0 : len(res)-len(".amazonaws.com")]
			}
		}
	case "ct.name":
		res = string(jdata.GetStringBytes("eventName"))
	case "ct.user":
		res = getUser(jdata)
	case "ct.region":
		res = string(jdata.GetStringBytes("awsRegion"))
	case "ct.srcip":
		res = string(jdata.GetStringBytes("sourceIPAddress"))
	case "ct.useragent":
		res = string(jdata.GetStringBytes("userAgent"))
	case "ct.info":
		res = getEvtInfo(jdata)
	case "ct.readonly":
		ro := jdata.GetBool("readOnly")
		if ro {
			res = "true"
		} else {
			oro := jdata.Get("readOnly")
			if oro == nil {
				//
				// Once in a while, events without the readOnly property appear. We try to interpret them with the manual
				// heuristic below.
				//
				ename := string(jdata.GetStringBytes("eventName"))
				if strings.HasPrefix(ename, "Start") || strings.HasPrefix(ename, "Stop") || strings.HasPrefix(ename, "Create") ||
					strings.HasPrefix(ename, "Destroy") || strings.HasPrefix(ename, "Delete") || strings.HasPrefix(ename, "Add") ||
					strings.HasPrefix(ename, "Remove") || strings.HasPrefix(ename, "Terminate") || strings.HasPrefix(ename, "Put") ||
					strings.HasPrefix(ename, "Associate") || strings.HasPrefix(ename, "Disassociate") || strings.HasPrefix(ename, "Attach") ||
					strings.HasPrefix(ename, "Detach") || strings.HasPrefix(ename, "Add") || strings.HasPrefix(ename, "Open") ||
					strings.HasPrefix(ename, "Close") || strings.HasPrefix(ename, "Wipe") || strings.HasPrefix(ename, "Update") ||
					strings.HasPrefix(ename, "Upgrade") || strings.HasPrefix(ename, "Unlink") || strings.HasPrefix(ename, "Assign") ||
					strings.HasPrefix(ename, "Unassign") || strings.HasPrefix(ename, "Suspend") || strings.HasPrefix(ename, "Set") ||
					strings.HasPrefix(ename, "Run") || strings.HasPrefix(ename, "Register") || strings.HasPrefix(ename, "Deregister") ||
					strings.HasPrefix(ename, "Reboot") || strings.HasPrefix(ename, "Purchase") || strings.HasPrefix(ename, "Modify") ||
					strings.HasPrefix(ename, "Initialize") || strings.HasPrefix(ename, "Enable") || strings.HasPrefix(ename, "Disable") ||
					strings.HasPrefix(ename, "Cancel") || strings.HasPrefix(ename, "Assign") || strings.HasPrefix(ename, "Admin") ||
					strings.HasPrefix(ename, "Activate") {
					res = "false"
				} else {
					res = "true"
				}
			} else {
				res = "false"
			}
		}
	case "s3.bucket":
		val := jdata.GetStringBytes("requestParameters", "bucketName")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case "s3.key":
		val := jdata.GetStringBytes("requestParameters", "key")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case "s3.host":
		val := jdata.GetStringBytes("requestParameters", "Host")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case "s3.uri":
		sbucket := jdata.GetStringBytes("requestParameters", "bucketName")
		if sbucket == nil {
			return false, ""
		}
		skey := jdata.GetStringBytes("requestParameters", "key")
		if skey == nil {
			return false, ""
		}
		res = fmt.Sprintf("s3://%s/%s", sbucket, skey)
	case "ec2.name":
		var iname string = ""
		jilist := jdata.GetArray("requestParameters", "tagSpecificationSet", "items")
		if jilist == nil {
			return false, ""
		}
		for _, item := range jilist {
			if string(item.GetStringBytes("resourceType")) != "instance" {
				continue
			}
			tlist := item.GetArray("tags")
			for _, tag := range tlist {
				key := string(tag.GetStringBytes("key"))
				if key == "Name" {
					iname = string(tag.GetStringBytes("value"))
					break
				}
			}
		}

		if iname == "" {
			return false, ""
		}
		res = iname
	default:
		return false, ""
	}

	return true, res
}

func getfieldU64(jdata *fastjson.Value, field string) (bool, uint64) {
	switch field {
	case "s3.bytes":
		var tot uint64 = 0
		in := jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			tot = tot + in.GetUint64()
		}
		out := jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + out.GetUint64()
		}
		return (in != nil || out != nil), tot
	case "s3.bytes.in":
		var tot uint64 = 0
		in := jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			tot = tot + in.GetUint64()
		}
		return (in != nil), tot
	case "s3.bytes.out":
		var tot uint64 = 0
		out := jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + out.GetUint64()
		}
		return (out != nil), tot
	case "s3.cnt.get":
		if string(jdata.GetStringBytes("eventName")) == "GetObject" {
			return true, 1
		}
		return false, 0
	case "s3.cnt.put":
		if string(jdata.GetStringBytes("eventName")) == "PutObject" {
			return true, 1
		}
		return false, 0
	case "s3.cnt.other":
		ename := string(jdata.GetStringBytes("eventName"))
		if ename == "GetObject" || ename == "PutObject" {
			return true, 1
		}
		return false, 0
	default:
		return false, 0
	}
}

//export plugin_event_to_string
func plugin_event_to_string(plgState unsafe.Pointer, data *C.char, datalen uint32) *C.char {
	var line string
	var src string
	var user string
	var err error

	pCtx := (*pluginContext)(state.Context(plgState))

	pCtx.jdata, err = pCtx.jparser.Parse(C.GoStringN(data, C.int(datalen)))
	if err != nil {
		pCtx.lastError = err
		line = "<invalid JSON: " + err.Error() + ">"
	} else {
		src = string(pCtx.jdata.GetStringBytes("eventSource"))

		if len(src) > len(".amazonaws.com") {
			srctrailer := src[len(src)-len(".amazonaws.com"):]
			if srctrailer == ".amazonaws.com" {
				src = src[0 : len(src)-len(".amazonaws.com")]
			}
		}

		user = getUser(pCtx.jdata)
		if user != "" {
			user = " " + user
		}

		info := getEvtInfo(pCtx.jdata)

		line = fmt.Sprintf("%s%s %s %s %s",
			pCtx.jdata.GetStringBytes("awsRegion"),
			user,
			src,
			pCtx.jdata.GetStringBytes("eventName"),
			info,
		)
	}

	return C.CString(line)
}

func extract_str(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string) {
	var err error
	pCtx := (*pluginContext)(state.Context(pluginState))

	// Decode the json, but only if we haven't done it yet for this event
	if evtnum != pCtx.jdataEvtnum {

		// Maybe temp--remove trailing null bytes from string
		data = bytes.Trim(data, "\x00")

		// For this plugin, events are always strings
		evtStr := string(data)

		pCtx.jdata, err = pCtx.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return false, ""
		}
		pCtx.jdataEvtnum = evtnum
	}

	return getfieldStr(pCtx.jdata, field)
}

func extract_u64(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64) {
	var err error
	pCtx := (*pluginContext)(state.Context(pluginState))

	// Decode the json, but only if we haven't done it yet for this event
	if evtnum != pCtx.jdataEvtnum {

		// For this plugin, events are always strings
		evtStr := string(data)

		pCtx.jdata, err = pCtx.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present.
			return false, 0
		}
		pCtx.jdataEvtnum = evtnum
	}

	return getfieldU64(pCtx.jdata, field)
}

//export plugin_extract_fields
func plugin_extract_fields(plgState unsafe.Pointer, evt *C.ss_plugin_event, numFields uint32, fields *C.ss_plugin_extract_field) int32 {
	log.Printf("[%s] plugin_extract_fields\n", PluginName)
	return wrappers.WrapExtractFuncs(plgState, unsafe.Pointer(evt), numFields, unsafe.Pointer(fields), extract_str, extract_u64)
}

///////////////////////////////////////////////////////////////////////////////
// The following code is part of the plugin interface. Do not remove it.
///////////////////////////////////////////////////////////////////////////////

//export plugin_register_async_extractor
func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
	return wrappers.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, extract_str, extract_u64)
}

//export plugin_next_batch
func plugin_next_batch(plgState unsafe.Pointer, openState unsafe.Pointer, nevts *uint32, retEvts **C.ss_plugin_event) int32 {
	evts, res := wrappers.NextBatch(plgState, openState, Next)

	if res == sdk.SSPluginSuccess {
		*retEvts = (*C.ss_plugin_event)(wrappers.Events(evts))
		*nevts = (uint32)(len(evts))
	}

	log.Printf("[%s] plugin_next_batch\n", PluginName)

	return res
}

func main() {
}
