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
// This plugin is a general json parser. It can be used to extract arbitrary
// fields from a buffer containing json data.
///////////////////////////////////////////////////////////////////////////////
package main

// #cgo CFLAGS: -I${SRCDIR}/../../
/*
#include <plugin_info.h>
*/
import "C"
import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"log"
	"strings"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go"
	"github.com/falcosecurity/plugin-sdk-go/state"
	"github.com/falcosecurity/plugin-sdk-go/wrappers"
	"github.com/valyala/fastjson"
)

// Plugin info
const (
	PluginRequiredApiVersion = "0.1.0"
	PluginName               = "json"
	PluginDescription        = "implements extracting arbitrary fields from inputs formatted as JSON"
	PluginContact            = "github.com/falcosecurity/plugins/"
	PluginVersion            = "0.1.0"
)

const verbose bool = false
const outBufSize uint32 = 65535

type pluginContext struct {
	jparser     fastjson.Parser
	jdata       *fastjson.Value
	jdataEvtnum uint64 // The event number jdata refers to. Used to know when we can skip the unmarshaling.
	lastError   error
}

//export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	return C.CString(PluginRequiredApiVersion)
}

//export plugin_get_type
func plugin_get_type() uint32 {
	return sdk.TypeExtractorPlugin
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
	if !verbose {
		log.SetOutput(ioutil.Discard)
	}

	log.Printf("[%s] plugin_init\n", PluginName)
	log.Printf("config string:\n%s\n", C.GoString(config))

	// Allocate the container for buffers and context
	pluginState := state.NewStateContainer()

	// Allocate the context struct and set it to the state
	pCtx := &pluginContext{}
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

//export plugin_get_name
func plugin_get_name() *C.char {
	return C.CString(PluginName)
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

//export plugin_get_fields
func plugin_get_fields() *C.char {
	flds := []sdk.FieldEntry{
		{Type: "string", Name: "json.value", ArgRequired: true, Desc: "Extracts a value from a JSON-encoded input. Syntax is json.value[<json pointer>], where <json pointer> is a json pointer (see https://datatracker.ietf.org/doc/html/rfc6901)"},
		{Type: "string", Name: "json.obj", Desc: "The full json message as a text string."},
		{Type: "string", Name: "json.rawtime", Desc: "The time of the event, identical to evt.rawtime."},
		{Type: "string", Name: "jevt.value", ArgRequired: true, Desc: "Alias for json.value, provided for backwards compatibility."},
		{Type: "string", Name: "jevt.obj", Desc: "Alias for json.obj, provided for backwards compatibility."},
		{Type: "string", Name: "jevt.rawtime", Desc: "Alias for json.rawtime, provided for backwards compatibility."},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		panic(err)
		return nil
	}

	return C.CString(string(b))
}

func extract_str(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string) {
	var res string
	var err error
	pCtx := (*pluginContext)(state.Context(pluginState))

	// As a very quick sanity check, only try to extract all if
	// the first character is '{' or '['
	if !(data[0] == '{' || data[0] == '[') {
		return false, ""
	}

	// Decode the json, but only if we haven't done it yet for this event
	if evtnum != pCtx.jdataEvtnum {

		// Try to parse the data as json
		evtStr := string(data)

		pCtx.jdata, err = pCtx.jparser.Parse(evtStr)
		if err != nil {
			// Not a json file, so not present
			return false, ""
		}
		pCtx.jdataEvtnum = evtnum
	}

	switch field {
	case "json.rawtime", "jevt.rawtime":
		return true, string(ts)
	case "json.value", "jevt.value":
		if arg[0] == '/' {
			arg = arg[1:]
		}
		hc := strings.Split(arg, "/")

		val := pCtx.jdata.GetStringBytes(hc...)
		if val == nil {
			return false, ""
		}
		res = string(val)
	case "json.obj", "jevt.obj":
		var out bytes.Buffer
		err = json.Indent(&out, data, "", "  ")
		if err != nil {
			return false, ""
		}
		res = string(out.Bytes())
	default:
		return false, ""
	}

	return true, res
}

func extract_u64(pluginState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64) {
	// No numeric fields for this plugin
	return false, 0
}

//export plugin_extract_fields
func plugin_extract_fields(plgState unsafe.Pointer, evt *C.struct_ss_plugin_event, numFields uint32, fields *C.struct_ss_plugin_extract_field) int32 {
	return wrappers.WrapExtractFuncs(plgState, unsafe.Pointer(evt), numFields, unsafe.Pointer(fields), extract_str, extract_u64)
}

///////////////////////////////////////////////////////////////////////////////
// The following code is part of the plugin interface. Do not remove it.
///////////////////////////////////////////////////////////////////////////////

//export plugin_register_async_extractor
func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
	return wrappers.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, extract_str, nil)
}

func main() {
}
