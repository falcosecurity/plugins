///////////////////////////////////////////////////////////////////////////////
// This plugin is a general json parser. It can be used to extract arbitrary
// fields from a buffer containing json data.
///////////////////////////////////////////////////////////////////////////////
package main

/*
#include <stdlib.h>

typedef void (*cb_wait_t)(void* wait_ctx);

typedef struct async_extractor_info
{
	uint64_t evtnum;
	uint32_t id;
	char* arg;
	char* data;
	uint32_t datalen;
	uint32_t field_present;
	char* res;
	cb_wait_t cb_wait;
	void* wait_ctx;
} async_extractor_info;
*/
import "C"
import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"
	"unsafe"

	"github.com/ldegio/libsinsp-plugin-sdk-go/pkg/sinsp"
	"github.com/valyala/fastjson"
)

// Plugin info
const (
	PluginID          uint32 = 3
	PluginName               = "jevt"
	PluginDescription        = "implements extracting arbitrary fields from inputs formatted as JSON"
)

const verbose bool = false
const outBufSize uint32 = 65535

type pluginContext struct {
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	lastError   error
}

var gLastError string = ""

//export plugin_get_type
func plugin_get_type() uint32 {
	return sinsp.TypeExtractorPlugin
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
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

	// Allocate the context struct and set it to the state
	pCtx := &pluginContext{}
	sinsp.SetContext(pluginState, unsafe.Pointer(pCtx))

	*rc = sinsp.ScapSuccess
	return pluginState
}

//export plugin_get_last_error
func plugin_get_last_error(plgState unsafe.Pointer) *C.char {
	log.Printf("[%s] plugin_get_last_error\n", PluginName)
	pCtx := (*pluginContext)(sinsp.Context(plgState))
	return C.CString(pCtx.lastError.Error())
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
	log.Printf("[%s] plugin_get_name\n", PluginName)
	return C.CString(PluginName)
}

//export plugin_get_description
func plugin_get_description() *C.char {
	log.Printf("[%s] plugin_get_description\n", PluginName)
	return C.CString(PluginDescription)
}

const FIELD_ID_VALUE uint32 = 0
const FIELD_ID_MSG uint32 = 1

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PluginName)
	flds := []sinsp.FieldEntry{
		{Type: "string", Name: "jevt.value", Desc: "allows to extract a value from a JSON-encoded input. Syntax is jevt.value[/x/y/z], where x,y and z are levels in the JSON hierarchy."},
		{Type: "string", Name: "jevt.json", Desc: "the full json message as a text string."},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		gLastError = err.Error()
		return nil
	}

	return C.CString(string(b))
}

//export plugin_extract_str
func plugin_extract_str(plgState unsafe.Pointer, evtnum uint64, id uint32, arg *C.char, data *C.char, datalen uint32) *C.char {
	var res string
	var err error
	pCtx := (*pluginContext)(sinsp.Context(plgState))

	// Decode the json, but only if we haven't done it yet for this event
	if evtnum != pCtx.jdataEvtnum {
		pCtx.jdata, err = pCtx.jparser.Parse(C.GoString(data))
		if err != nil {
			//
			// Not a json file. We return nil to indicate that the field is not
			// present.
			//
			return nil
		}
		pCtx.jdataEvtnum = evtnum
	}

	switch id {
	case FIELD_ID_VALUE:
		sarg := C.GoString(arg)
		if sarg[0] == '/' {
			sarg = sarg[1:]
		}
		hc := strings.Split(sarg, "/")

		val := pCtx.jdata.GetStringBytes(hc...)
		if val == nil {
			return nil
		}
		res = string(val)
	case FIELD_ID_MSG:
		var out bytes.Buffer
		err = json.Indent(&out, []byte(C.GoString(data)), "", "  ")
		if err != nil {
			return nil
		}
		res = string(out.Bytes())
	default:
		res = "<NA>"
	}

	// NULL terminate the result so C will like it
	res += "\x00"

	// Copy the the line into the event buffer
	sinsp.CopyToBuffer(plgState, []byte(res))
	// todo(leogr): try a way to avoid casting here
	return (*C.char)(unsafe.Pointer(sinsp.Buffer(plgState)))
}

///////////////////////////////////////////////////////////////////////////////
// XXX To be moved
///////////////////////////////////////////////////////////////////////////////

//export plugin_register_async_extractor
func plugin_register_async_extractor(plgState unsafe.Pointer, info *C.async_extractor_info) int32 {
	go func() {
		for sinsp.Wait(unsafe.Pointer(info)) {
			(*info).res = plugin_extract_str(plgState, uint64(info.evtnum),
				uint32(info.id),
				info.arg,
				info.data,
				uint32(info.datalen))
		}
	}()
	return sinsp.ScapSuccess
}

///////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////

func main() {
}
