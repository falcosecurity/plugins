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

package main

// #cgo CFLAGS: -I${SRCDIR}/../../
/*
#include <plugin_info.h>
*/
import "C"
import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"strconv"
	"time"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go"
	"github.com/falcosecurity/plugin-sdk-go/state"
	"github.com/falcosecurity/plugin-sdk-go/wrappers"
)

// Plugin consts
const (
	PluginRequiredApiVersion        = "1.0.0"
	PluginID                 uint32 = 3
	PluginName                      = "dummy"
	PluginDescription               = "Reference plugin for educational purposes"
	PluginContact                   = "github.com/falcosecurity/plugins"
	PluginVersion                   = "1.0.0"
	PluginEventSource               = "dummy"
)

///////////////////////////////////////////////////////////////////////////////

type pluginState struct {

	// A copy of the config provided to plugin_init()
	config string

	// When a function results in an error, this is set and can be
	// retrieved in plugin_get_last_error().
	lastError error

	// This reflects potential internal state for the plugin. In
	// this case, the plugin is configured with a jitter (e.g. a
	// random amount to add to the sample with each call to Next()
	jitter uint64

	// Will be used to randomize samples
	rand *rand.Rand
}

type instanceState struct {

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

//export plugin_get_required_api_version
func plugin_get_required_api_version() *C.char {
	log.Printf("[%s] plugin_get_required_api_version\n", PluginName)
	return C.CString(PluginRequiredApiVersion)
}

//export plugin_get_type
func plugin_get_type() uint32 {
	log.Printf("[%s] plugin_get_type\n", PluginName)
	return sdk.TypeSourcePlugin
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

//export plugin_get_contact
func plugin_get_contact() *C.char {
	log.Printf("[%s] plugin_get_contact\n", PluginName)
	return C.CString(PluginContact)
}

//export plugin_get_version
func plugin_get_version() *C.char {
	log.Printf("[%s] plugin_get_version\n", PluginName)
	return C.CString(PluginVersion)
}

//export plugin_get_event_source
func plugin_get_event_source() *C.char {
	log.Printf("[%s] plugin_get_event_source\n", PluginName)
	return C.CString(PluginEventSource)
}

//export plugin_get_fields
func plugin_get_fields() *C.char {
	log.Printf("[%s] plugin_get_fields\n", PluginName)

	flds := []sdk.FieldEntry{
		{Type: "uint64", Name: "dummy.divisible", ArgRequired: true, Desc: "Return 1 if the value is divisible by the provided divisor, 0 otherwise"},
		{Type: "uint64", Name: "dummy.value", Desc: "The sample value in the event"},
		{Type: "string", Name: "dummy.strvalue", Desc: "The sample value in the event, as a string"},
	}

	b, err := json.Marshal(&flds)
	if err != nil {
		return nil
	}

	return C.CString(string(b))
}

//export plugin_get_last_error
func plugin_get_last_error(pState unsafe.Pointer) *C.char {
	log.Printf("[%s] plugin_get_last_error\n", PluginName)

	ps := (*pluginState)(state.Context(pState))

	if ps.lastError != nil {
		str := C.CString(ps.lastError.Error())
		ps.lastError = nil
		return str
	}
	return nil
}

//export plugin_init
func plugin_init(config *C.char, rc *int32) unsafe.Pointer {
	cfg := C.GoString(config)
	log.Printf("[%s] plugin_init config=%s\n", PluginName, cfg)

	// The format of cfg is a json object with a single param
	// "jitter", e.g. {"jitter": 10}
	var obj map[string]uint64
	err := json.Unmarshal([]byte(cfg), &obj)
	if err != nil {
		*rc = sdk.SSPluginFailure
		return nil
	}
	if _, ok := obj["jitter"]; !ok {
		*rc = sdk.SSPluginFailure
		return nil
	}

	ps := &pluginState{
		config:    cfg,
		lastError: nil,
		jitter:    obj["jitter"],
		rand:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	// In order to avoid breaking the Cgo pointer passing rules,
	// we wrap the plugin state in a handle using
	// state.NewStateContainer()
	handle := state.NewStateContainer()
	state.SetContext(handle, unsafe.Pointer(ps))

	*rc = sdk.SSPluginSuccess

	return handle
}

//export plugin_destroy
func plugin_destroy(pState unsafe.Pointer) {
	log.Printf("[%s] plugin_destroy\n", PluginName)

	// This frees the pluginState struct inside this handle
	state.Free(pState)
}

//export plugin_open
func plugin_open(pState unsafe.Pointer, params *C.char, rc *int32) unsafe.Pointer {
	prms := C.GoString(params)
	log.Printf("[%s] plugin_open, params: %s\n", PluginName, prms)

	ps := (*pluginState)(state.Context(pState))

	// The format of params is a json object with two params:
	// - "start", which denotes the initial value of sample
	// - "maxEvents": which denotes the number of events to return before EOF.
	// Example:
	// {"start": 1, "maxEvents": 1000}
	var obj map[string]uint64
	err := json.Unmarshal([]byte(prms), &obj)
	if err != nil {
		ps.lastError = fmt.Errorf("Params %s could not be parsed: %v", prms, err)
		*rc = sdk.SSPluginFailure
		return nil
	}
	if _, ok := obj["start"]; !ok {
		ps.lastError = fmt.Errorf("Params %s did not contain start property", prms)
		*rc = sdk.SSPluginFailure
		return nil
	}

	if _, ok := obj["maxEvents"]; !ok {
		ps.lastError = fmt.Errorf("Params %s did not contain maxEvents property", prms)
		*rc = sdk.SSPluginFailure
		return nil
	}

	is := &instanceState{
		initParams: prms,
		maxEvents:  obj["maxEvents"],
		counter:    0,
		sample:     obj["start"],
	}

	handle := state.NewStateContainer()
	state.SetContext(handle, unsafe.Pointer(is))

	*rc = sdk.SSPluginSuccess
	return handle
}

//export plugin_close
func plugin_close(pState unsafe.Pointer, iState unsafe.Pointer) {
	log.Printf("[%s] plugin_close\n", PluginName)

	state.Free(iState)
}

// This higher-level function will be called by both plugin_next and plugin_next_batch
func Next(pState unsafe.Pointer, iState unsafe.Pointer) (*sdk.PluginEvent, int32) {
	log.Printf("[%s] Next\n", PluginName)

	ps := (*pluginState)(state.Context(pState))
	is := (*instanceState)(state.Context(iState))

	is.counter++

	// Return eof if reached maxEvents
	if is.counter >= is.maxEvents {
		return nil, sdk.SSPluginEOF
	}

	// Increment sample by 1, also add a jitter of [0:jitter]
	is.sample += 1 + uint64(ps.rand.Int63n(int64(ps.jitter+1)))

	// The representation of a dummy event is the sample as a string.
	str := strconv.Itoa(int(is.sample))

	// It is not mandatory to set the Timestamp of the event (it
	// would be filled in by the framework if set to uint_max),
	// but it's a good practice.
	//
	// Also note that the Evtnum is not set, as event numbers are
	// assigned by the plugin framework.
	evt := &sdk.PluginEvent{
		Data:      []byte(str),
		Timestamp: uint64(time.Now().Unix()) * 1000000000,
	}

	return evt, sdk.SSPluginSuccess
}

//export plugin_next
func plugin_next(pState unsafe.Pointer, iState unsafe.Pointer, retEvt **C.ss_plugin_event) int32 {
	log.Printf("[%s] plugin_next\n", PluginName)

	evt, res := Next(pState, iState)
	if res == sdk.SSPluginSuccess {
		*retEvt = (*C.ss_plugin_event)(wrappers.Events([]*sdk.PluginEvent{evt}))
	}

	return res
}

// This wraps the simpler Next() function above and takes care of the
// details of assembling multiple events.

//export plugin_next_batch
func plugin_next_batch(pState unsafe.Pointer, iState unsafe.Pointer, nevts *uint32, retEvts **C.ss_plugin_event) int32 {
	evts, res := wrappers.NextBatch(pState, iState, Next)

	if res == sdk.SSPluginSuccess {
		*retEvts = (*C.ss_plugin_event)(wrappers.Events(evts))
		*nevts = (uint32)(len(evts))
	}

	log.Printf("[%s] plugin_next_batch\n", PluginName)

	return res
}

//export plugin_event_to_string
func plugin_event_to_string(pState unsafe.Pointer, data *C.uint8_t, datalen uint32) *C.char {

	// This can blindly convert the C.uint8_t to a *C.char, as this
	// plugin always returns a C string as the event buffer.
	evtStr := C.GoStringN((*C.char)(unsafe.Pointer(data)), C.int(datalen))

	log.Printf("[%s] plugin_event_to_string %s\n", PluginName, evtStr)

	// The string representation of an event is a json object with the sample
	s := fmt.Sprintf("{\"sample\": \"%s\"}", evtStr)
	return C.CString(s)
}

// This plugin only needs to implement simpler single-field versions
// of extract_str/extract_u64. A utility function will take these
// functions as arguments and handle the work of conversion/iterating
// over fields.
func extract_str(pState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, string) {
	log.Printf("[%s] extract_str\n", PluginName)

	ps := (*pluginState)(state.Context(pState))

	switch field {
	case "dummy.strvalue":
		return true, string(data)
	default:
		ps.lastError = fmt.Errorf("No known field %s", field)
		return false, ""
	}
}

func extract_u64(pState unsafe.Pointer, evtnum uint64, data []byte, ts uint64, field string, arg string) (bool, uint64) {
	log.Printf("[%s] extract_str\n", PluginName)

	ps := (*pluginState)(state.Context(pState))

	val, err := strconv.Atoi(string(data))
	if err != nil {
		return false, 0
	}

	switch field {
	case "dummy.value":
		return true, uint64(val)
	case "dummy.divisible":
		// The argument contains the divisor as a string
		divisor, err := strconv.Atoi(arg)
		if err != nil {
			ps.lastError = fmt.Errorf("Argument to dummy.divisible %s could not be converted to number", arg)
			return false, 0
		}
		if val%divisor == 0 {
			return true, 1
		} else {
			return true, 0
		}
	default:
		ps.lastError = fmt.Errorf("No known field %s", field)
		return false, 0
	}
}

// This wraps the simple extract functions above and is the actual exported function

//export plugin_extract_fields
func plugin_extract_fields(pState unsafe.Pointer, evt *C.struct_ss_plugin_event, numFields uint32, fields *C.struct_ss_plugin_extract_field) int32 {
	log.Printf("[%s] plugin_extract_fields\n", PluginName)
	return wrappers.WrapExtractFuncs(pState, unsafe.Pointer(evt), numFields, unsafe.Pointer(fields), extract_str, extract_u64)
}

// This wraps the simple extract functions above to allow for multiple
// field extractions in a single function call. Although provided here
// for example purposes, there is a CPU cost of async extraction and
// it should only be defined if a plugin has a very high rate of
// events (> thousands/second) and where the CPU cost of async
// extraction is worth avoiding the overhead of C-to-Go function calls
// for individual calls to plugin_extract_fields

//export plugin_register_async_extractor
func plugin_register_async_extractor(pluginState unsafe.Pointer, asyncExtractorInfo unsafe.Pointer) int32 {
	return wrappers.RegisterAsyncExtractors(pluginState, asyncExtractorInfo, extract_str, extract_u64)
}

func main() {}
