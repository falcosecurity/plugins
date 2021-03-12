///////////////////////////////////////////////////////////////////////////////
// This plugin reads reading cloudtrail files from a local directory or from a
// remote S3 bucket. Cloudtrail events are dispatched to the engine one by one,
// in their original json form, so the full data is retained.
// The plugin also exports a bunch of filter fields useful for cloudtrail
// analysis (see plugin_get_fields() for the list).
///////////////////////////////////////////////////////////////////////////////

package main

/*
#include <stdlib.h>
#include <inttypes.h>
*/
import "C"
import (
	"bytes"
	"compress/gzip"
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
	"github.com/ldegio/libsinsp-plugin-sdk-go/pkg/sinsp"
	"github.com/valyala/fastjson"
)

// Plugin info
const (
	PluginID          uint32 = 2
	PluginName               = "cloudtrail"
	PluginDescription        = "reads cloudtrail JSON data saved to file in the directory specified in the settings"
)

const s3DownloadConcurrency = 64
const verbose bool = false
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

///////////////////////////////////////////////////////////////////////////////
// PLUGIN STATE STRUCTS
///////////////////////////////////////////////////////////////////////////////

// This is the global plugin state, identifying an instance of this plugin
type pluginContext struct {
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	lastError   error
}

// This is the open state, identifying an open instance reading cloudtrail files from
// a local directory or from a remote S3 bucket
type openContext struct {
	isDataFromS3       bool
	cloudTrailFilesDir string
	files              []fileInfo
	curFileNum         uint32
	evtJSONStrings     [][]byte
	evtJSONListPos     int
	s3                 s3State
	nextJParser        fastjson.Parser
	nextBatchLastTs    uint64
	nextBatchLastData  []byte
}

///////////////////////////////////////////////////////////////////////////////
// PLUGIN INTERFACE IMPLEMENTATION
///////////////////////////////////////////////////////////////////////////////

//export plugin_get_type
func plugin_get_type() uint32 {
	return sinsp.TypeSourcePlugin
}

//export plugin_init
func plugin_init(config *C.char, minAPIVersion *uint32, rc *int32) unsafe.Pointer {
	if !verbose {
		log.SetOutput(ioutil.Discard)
	}

	log.Printf("[%s] plugin_init\n", PluginName)
	log.Printf("config string:\n%s\n", C.GoString(config))

	// Allocate the container for buffers and context
	pluginState := sinsp.NewStateContainer()

	// We need a piece of memory to share data with the C code that we can use
	// as storage for functions like plugin_event_to_string and plugin_extract_str,
	// so that their results can be shared without allocations or data copies.
	sinsp.MakeBuffer(pluginState, outBufSize)

	// Allocate the context struct attach it to the state
	pCtx := &pluginContext{
		jdataEvtnum: math.MaxUint64,
	}
	sinsp.SetContext(pluginState, unsafe.Pointer(pCtx))

	*minAPIVersion = 1
	*rc = sinsp.ScapSuccess
	return pluginState
}

//export plugin_get_last_error
func plugin_get_last_error(plgState unsafe.Pointer) *C.char {
	log.Printf("[%s] plugin_get_last_error\n", PluginName)
	pCtx := (*pluginContext)(sinsp.Context(plgState))
	if pCtx.lastError != nil {
		return C.CString(pCtx.lastError.Error())
	}

	return C.CString("no error")
}

//export plugin_destroy
func plugin_destroy(plgState unsafe.Pointer) {
	log.Printf("[%s] plugin_destroy\n", PluginName)
	sinsp.Free(plgState)
}

//export plugin_get_id
func plugin_get_id() uint32 {
	log.Printf("[%s] plugin_get_id\n", PluginName)
	return PluginID
}

//export plugin_get_name
func plugin_get_name() *C.char {
	//	log.Printf("[%s] plugin_get_name\n", PluginName)
	return C.CString(PluginName)
}

//export plugin_get_description
func plugin_get_description() *C.char {
	log.Printf("[%s] plugin_get_description\n", PluginName)
	return C.CString(PluginDescription)
}

// Filed identifiers
const (
	FieldIDCtID = iota
	FieldIDCtTime
	FieldIDCtSrc
	FieldIDCtName
	FieldIDCtUser
	FieldIDCtRegion
	FieldIDCtSrcIP
	FieldIDCtUserAgent
	FieldIDCtInfo
	FieldIDCtIsKey
	FieldIDS3Bucket
	FieldIDS3Key
	FieldIDS3Host
	FieldIDS3Uri
	FieldIDS3Bytes
	FieldIDS3BytesIn
	FieldIDS3BytesOut
	FieldIDS3CntGet
	FieldIDS3CntPut
	FieldIDS3CntOther
	FieldIDEc2Name
)

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PluginName)
	flds := []sinsp.FieldEntry{
		{Type: "string", ID: FieldIDCtID, Name: "ct.id", Desc: "the unique ID of the cloudtrail event (eventID in the json)."},
		{Type: "string", ID: FieldIDCtTime, Name: "ct.time", Desc: "the timestamp of the cloudtrail event (eventTime in the json)."},
		{Type: "string", ID: FieldIDCtSrc, Name: "ct.src", Desc: "the source of the cloudtrail event (eventSource in the json, without the '.amazonaws.com' trailer)."},
		{Type: "string", ID: FieldIDCtName, Name: "ct.name", Desc: "the name of the cloudtrail event (eventName in the json)."},
		{Type: "string", ID: FieldIDCtUser, Name: "ct.user", Desc: "the user of the cloudtrail event (userIdentity.userName in the json)."},
		{Type: "string", ID: FieldIDCtRegion, Name: "ct.region", Desc: "the region of the cloudtrail event (awsRegion in the json)."},
		{Type: "string", ID: FieldIDCtSrcIP, Name: "ct.srcip", Desc: "the IP address generating the event (sourceIPAddress in the json)."},
		{Type: "string", ID: FieldIDCtUserAgent, Name: "ct.useragent", Desc: "the user agent generating the event (userAgent in the json)."},
		{Type: "string", ID: FieldIDCtInfo, Name: "ct.info", Desc: "summary information about the event. This varies depending on the event type and, for some events, it contains event-specific details."},
		{Type: "string", ID: FieldIDCtIsKey, Name: "ct.is_key", Desc: "'true' if the event modifies the state (e.g. RunInstances, CreateLoadBalancer...). 'false' otherwise."},
		{Type: "string", ID: FieldIDS3Bucket, Name: "s3.bucket", Desc: "the bucket name for s3 events."},
		{Type: "string", ID: FieldIDS3Key, Name: "s3.key", Desc: "the key name for s3 events."},
		{Type: "string", ID: FieldIDS3Host, Name: "s3.host", Desc: "the host name for s3 events."},
		{Type: "string", ID: FieldIDS3Uri, Name: "s3.uri", Desc: "the s3 URI (s3://<bucket>/<key>) for s3 events."},
		{Type: "uint64", ID: FieldIDS3Bytes, Name: "s3.bytes", Desc: "the size of an s3 download or upload, in bytes."},
		{Type: "uint64", ID: FieldIDS3BytesIn, Name: "s3.bytes.in", Desc: "the size of an s3 upload, in bytes."},
		{Type: "uint64", ID: FieldIDS3BytesOut, Name: "s3.bytes.out", Desc: "the size of an s3 download, in bytes."},
		{Type: "uint64", ID: FieldIDS3CntGet, Name: "s3.cnt.get", Desc: "the number of get operations. This field is 1 for GetObject events, 0 otherwise."},
		{Type: "uint64", ID: FieldIDS3CntPut, Name: "s3.cnt.put", Desc: "the number of put operations. This field is 1 for PutObject events, 0 otherwise."},
		{Type: "uint64", ID: FieldIDS3CntOther, Name: "s3.cnt.other", Desc: "the number of non I/O operations. This field is 0 for GetObject and PutObject events, 1 for all the other events."},
		{Type: "string", ID: FieldIDEc2Name, Name: "ec2.name", Desc: "the name of the ec2 instances, typically stored in the instance tags."},
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
	*rc = sinsp.ScapFailure

	oCtx.isDataFromS3 = false

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
	*rc = sinsp.ScapSuccess
}

func openS3(pCtx *pluginContext, oCtx *openContext, params *C.char, rc *int32) {
	*rc = sinsp.ScapFailure
	input := C.GoString(params)

	oCtx.isDataFromS3 = true

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

	// Fetch the list of keys
	oCtx.s3.awsSess = session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	oCtx.s3.awsSvc = s3.New(oCtx.s3.awsSess)

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
		*rc = sinsp.ScapFailure
		return
	}

	oCtx.s3.downloader = s3manager.NewDownloader(oCtx.s3.awsSess)
	*rc = sinsp.ScapSuccess
}

//export plugin_open
func plugin_open(plgState unsafe.Pointer, params *C.char, rc *int32) unsafe.Pointer {
	log.Printf("[%s] plugin_open\n", PluginName)
	pCtx := (*pluginContext)(sinsp.Context(plgState))

	// Allocate the context struct for this open instance
	oCtx := &openContext{}

	// Perform the open
	input := C.GoString(params)
	if len(input) >= 5 && input[:5] == "s3://" {
		openS3(pCtx, oCtx, params, rc)
	} else {
		openLocal(pCtx, oCtx, params, rc)
	}

	if *rc != sinsp.ScapSuccess {
		return nil
	}

	// Allocate the library-compatible container for the open context
	openState := sinsp.NewStateContainer()

	// We need a piece of memory to share data with the C code: a buffer that
	// contains the events that we create and send to the engine through next()
	sinsp.MakeBuffer(openState, sinsp.MaxNextBufSize)

	// Create an array of download buffers that will be used to concurrently
	// download files from s3
	oCtx.s3.DownloadBufs = make([][]byte, s3DownloadConcurrency)

	// Tie the just created state to the open context
	//
	sinsp.SetContext(openState, unsafe.Pointer(oCtx))

	// Allocate buffer for next()
	return openState
}

//export plugin_close
func plugin_close(plgState unsafe.Pointer, openState unsafe.Pointer) {
	log.Printf("[%s] plugin_close\n", PluginName)
	if openState != nil {
		sinsp.Free(openState)
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

func readNextFileS3(oCtx *openContext) ([]byte, error) {
	if oCtx.s3.curBuf < oCtx.s3.nFilledBufs {
		curBuf := oCtx.s3.curBuf
		oCtx.s3.curBuf++
		return oCtx.s3.DownloadBufs[curBuf], nil
	}

	dlErrChan = make(chan error, s3DownloadConcurrency)
	k := oCtx.s3.lastDownloadedFileNum
	oCtx.s3.nFilledBufs = min(s3DownloadConcurrency, len(oCtx.files)-k)
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

	oCtx.s3.lastDownloadedFileNum += s3DownloadConcurrency

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
func Next(plgState unsafe.Pointer, openState unsafe.Pointer, data *[]byte, ts *uint64) int32 {
	// log.Printf("[%s] plugin_next\n", PluginName)
	var tmpStr []byte
	var err error

	pCtx := (*pluginContext)(sinsp.Context(plgState))
	oCtx := (*openContext)(sinsp.Context(openState))

	// Only open the next file once we're sure that the content of the previous one has been full consumed
	if oCtx.evtJSONListPos == len(oCtx.evtJSONStrings) {
		// Open the next file and bring its content into memeory
		if oCtx.curFileNum >= uint32(len(oCtx.files)) {
			return sinsp.ScapEOF
		}

		file := oCtx.files[oCtx.curFileNum]
		oCtx.curFileNum++

		if oCtx.isDataFromS3 {
			tmpStr, err = readNextFileS3(oCtx)
		} else {
			tmpStr, err = readFileLocal(file.name)
		}
		if err != nil {
			pCtx.lastError = err
			return sinsp.ScapFailure
		}

		// The file can be gzipped. If it is, we unzip it.
		if file.isCompressed {
			gr, err := gzip.NewReader(bytes.NewBuffer(tmpStr))
			defer gr.Close()
			zdata, err := ioutil.ReadAll(gr)
			if err != nil {
				return sinsp.ScapTimeout
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
		*data = oCtx.evtJSONStrings[oCtx.evtJSONListPos]
		cr, err = oCtx.nextJParser.Parse(string(*data))
		if err != nil {
			// Not json? Just skip this event.
			oCtx.evtJSONListPos++
			return sinsp.ScapTimeout
		}

		oCtx.evtJSONListPos++
	} else {
		// Json not int the expected format. Just skip this event.
		oCtx.evtJSONListPos++
		return sinsp.ScapTimeout
	}

	// Extract the timestamp
	t1, err := time.Parse(
		time.RFC3339,
		string(cr.GetStringBytes("eventTime")))
	if err != nil {
		//
		// We assume this is just some spurious data and we continue
		//
		return sinsp.ScapTimeout
	}
	*ts = uint64(t1.Unix()) * 1000000000

	ets := string(cr.GetStringBytes("eventType"))
	if ets == "AwsCloudTrailInsight" {
		return sinsp.ScapTimeout
	}

	// NULL-terminate the json data string, so that C will like it
	*data = append(*data, 0)

	// Make sure the event is not too big for the engine
	if len(*data) > int(sinsp.MaxEvtSize) {
		pCtx.lastError = fmt.Errorf("cloudwatch message too long: %d, max %d supported", len(*data), sinsp.MaxEvtSize)
		return sinsp.ScapFailure
	}

	return sinsp.ScapSuccess
}

//export plugin_next
func plugin_next(plgState unsafe.Pointer, openState unsafe.Pointer, data **byte, datalen *uint32, ts *uint64) int32 {
	var nextData []byte

	res := Next(plgState, openState, &nextData, ts)
	if res == sinsp.ScapSuccess {
		// Copy to and return the event buffer
		*datalen = sinsp.CopyToBuffer(openState, nextData)
		*data = sinsp.Buffer(openState)
	}

	return res
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
			jun := jdata.GetStringBytes("sessionContext", "sessionIssuer", "userName")
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

	present, evtname = getfieldStr(jdata, FieldIDCtName)
	if !present {
		return "<invalid cloudtrail event: eventName field missing>"
	}

	switch evtname {
	case "GetObject", "PutObject":
		present, uri := getfieldStr(jdata, FieldIDS3Uri)
		if present {
			info = fmt.Sprintf("%s", uri)
		} else {
			info = "<URI missing>"
		}

	case "PutBucketPublicAccessBlock":
		info = ""
		jpac := jdata.GetObject("requestParameters", "PublicAccessBlockConfiguration")
		if jpac != nil {
			info += fmt.Sprintf("BlockPublicAcls:%v BlockPublicPolicy:%v IgnorePublicAcls:%v RestrictPublicBuckets:%v ",
				jdata.GetBool("BlockPublicAcls"),
				jdata.GetBool("BlockPublicPolicy"),
				jdata.GetBool("IgnorePublicAcls"),
				jdata.GetBool("RestrictPublicBuckets"),
			)
		}
	default:
		info = ""
	}

	return info
}

func getfieldStr(jdata *fastjson.Value, id uint32) (bool, string) {
	var res string

	switch id {
	case FieldIDCtID:
		res = string(jdata.GetStringBytes("eventID"))
	case FieldIDCtTime:
		res = string(jdata.GetStringBytes("eventTime"))
	case FieldIDCtSrc:
		res = string(jdata.GetStringBytes("eventSource"))

		if len(res) > len(".amazonaws.com") {
			srctrailer := res[len(res)-len(".amazonaws.com"):]
			if srctrailer == ".amazonaws.com" {
				res = res[0 : len(res)-len(".amazonaws.com")]
			}
		}
	case FieldIDCtName:
		res = string(jdata.GetStringBytes("eventName"))
	case FieldIDCtUser:
		res = getUser(jdata)
	case FieldIDCtRegion:
		res = string(jdata.GetStringBytes("awsRegion"))
	case FieldIDCtSrcIP:
		res = string(jdata.GetStringBytes("sourceIPAddress"))
	case FieldIDCtUserAgent:
		res = string(jdata.GetStringBytes("userAgent"))
	case FieldIDCtInfo:
		res = getEvtInfo(jdata)
	case FieldIDCtIsKey:
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
			res = "true"
		} else {
			res = "false"
		}
	case FieldIDS3Bucket:
		val := jdata.GetStringBytes("requestParameters", "bucketName")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case FieldIDS3Key:
		val := jdata.GetStringBytes("requestParameters", "key")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case FieldIDS3Host:
		val := jdata.GetStringBytes("requestParameters", "Host")
		if val == nil {
			return false, ""
		}
		res = string(val)
	case FieldIDS3Uri:
		sbucket := jdata.GetStringBytes("requestParameters", "bucketName")
		if sbucket == nil {
			return false, ""
		}
		skey := jdata.GetStringBytes("requestParameters", "key")
		if skey == nil {
			return false, ""
		}
		res = fmt.Sprintf("s3://%s/%s", sbucket, skey)
	case FieldIDEc2Name:
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

//export plugin_event_to_string
func plugin_event_to_string(plgState unsafe.Pointer, data *C.char, datalen uint32) *byte {
	// log.Printf("[%s] plugin_event_to_string\n", PluginName)
	var line string
	var src string
	var user string
	var err error

	pCtx := (*pluginContext)(sinsp.Context(plgState))

	pCtx.jdata, err = pCtx.jparser.Parse(C.GoString(data))
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

	// NULL-terminate the json data string, so that C will like it
	line += "\x00"

	sinsp.CopyToBuffer(plgState, []byte(line))
	return sinsp.Buffer(plgState)
}

//export plugin_extract_str
func plugin_extract_str(plgState unsafe.Pointer, evtnum uint64, id uint32, arg *byte, data *byte, datalen uint32) *byte {
	var res string
	var err error
	pCtx := (*pluginContext)(sinsp.Context(plgState))

	// Decode the json, but only if we haven't done it yet for this event
	if evtnum != pCtx.jdataEvtnum {
		pCtx.jdata, err = pCtx.jparser.Parse(C.GoString(
			(*C.char)(unsafe.Pointer(data)),
		))
		if err != nil {
			// Not a json file. We return nil to indicate that the field is not
			// present.
			return nil
		}
		pCtx.jdataEvtnum = evtnum
	}

	present, val := getfieldStr(pCtx.jdata, id)
	if !present {
		return nil
	}

	res = val

	// NULL terminate the result so C will like it
	res += "\x00"

	sinsp.CopyToBuffer(plgState, []byte(res))

	return sinsp.Buffer(plgState)
}

//export plugin_extract_u64
func plugin_extract_u64(plgState unsafe.Pointer, evtnum uint64, id uint32, arg *byte, data *byte, datalen uint32, fieldPresent *uint32) uint64 {
	var err error
	*fieldPresent = 0
	pCtx := (*pluginContext)(sinsp.Context(plgState))

	// Decode the json, but only if we haven't done it yet for this event
	if evtnum != pCtx.jdataEvtnum {
		pCtx.jdata, err = pCtx.jparser.Parse(C.GoString((*C.char)(unsafe.Pointer(data))))
		if err != nil {
			// Not a json file. We return 0 and *fieldPresent=0 to indicate
			// that the field is not present.
			return 0
		}
		pCtx.jdataEvtnum = evtnum
	}

	switch id {
	case FieldIDS3Bytes:
		var tot uint64 = 0
		in := pCtx.jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			tot = tot + in.GetUint64()
		}
		out := pCtx.jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + out.GetUint64()
		}
		*fieldPresent = 1
		return tot
	case FieldIDS3BytesIn:
		var tot uint64 = 0
		in := pCtx.jdata.Get("additionalEventData", "bytesTransferredIn")
		if in != nil {
			tot = tot + in.GetUint64()
		}
		*fieldPresent = 1
		return tot
	case FieldIDS3BytesOut:
		var tot uint64 = 0
		out := pCtx.jdata.Get("additionalEventData", "bytesTransferredOut")
		if out != nil {
			tot = tot + out.GetUint64()
		}
		*fieldPresent = 1
		return tot
	case FieldIDS3CntGet:
		if string(pCtx.jdata.GetStringBytes("eventName")) == "GetObject" {
			*fieldPresent = 1
			return 1
		}
		return 0
	case FieldIDS3CntPut:
		if string(pCtx.jdata.GetStringBytes("eventName")) == "PutObject" {
			*fieldPresent = 1
			return 1
		}
		return 0
	case FieldIDS3CntOther:
		ename := string(pCtx.jdata.GetStringBytes("eventName"))
		if ename == "GetObject" || ename == "PutObject" {
			*fieldPresent = 1
			return 0
		}
		return 1
	default:
		return 0
	}
}

///////////////////////////////////////////////////////////////////////////////
// The following code is part of the plugin interface. Do not remove it.
///////////////////////////////////////////////////////////////////////////////

//export plugin_register_async_extractor
func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
	log.Printf("[%s] plugin_register_async_extractor\n", PluginName)
	return sinsp.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, plugin_extract_str, plugin_extract_u64)
}

//export plugin_next_batch
func plugin_next_batch(plgState unsafe.Pointer, openState unsafe.Pointer, data **byte, datalen *uint32) int32 {
	return sinsp.NextBatch(plgState, openState, data, datalen, Next)
}

func main() {
}
