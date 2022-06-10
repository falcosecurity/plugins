//go:build (linux && cgo) || (darwin && cgo) || (freebsd && cgo)
// +build linux,cgo darwin,cgo freebsd,cgo

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

package loader

import (
	"encoding/json"
	"errors"
	"runtime"
	"unsafe"

	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
)

/*
#cgo linux LDFLAGS: -ldl

#include "loader.h"
#include <stdlib.h>

static uint32_t plugin_loader_load_max_errlen()
{
    return PLUGIN_LOADER_MAX_ERRLEN;
}

static uint32_t pl_get_static_u32(uint32_t (*f)())
{
    return f();
}

static const char* pl_get_static_str(const char *(*f)())
{
    return f();
}

static const char* pl_call_void(void *(*f)())
{
    return f();
}

static ss_plugin_t* pl_init(plugin_api* p, const char *cfg, ss_plugin_rc *rc)
{
    return p->init(cfg, rc);
}
*/
import "C"

type Plugin struct {
	lib        *C.plugin_loader_library_t
	info       plugins.Info
	initSchema sdk.SchemaInfo
	state      *C.ss_plugin_t
}

func NewPlugin(path string) (*Plugin, error) {
	// map buffer for err string
	errBuf := C.malloc(C.uint64_t(C.plugin_loader_load_max_errlen()))
	defer C.free(unsafe.Pointer(errBuf))

	// load library
	p := &Plugin{}
	s := C.CString(path)
	p.lib = C.plugin_loader_load(s, (*C.char)(unsafe.Pointer(errBuf)))
	if p.lib == nil {
		return nil, errors.New(C.GoString((*C.char)(unsafe.Pointer(errBuf))))
	}

	// unload library at garbage collection time
	runtime.SetFinalizer(p, func(pl *Plugin) {
		C.plugin_loader_unload(pl.lib)
	})

	// read static info
	p.info = plugins.Info{
		Version:             ptr.GoString(unsafe.Pointer(C.pl_get_static_str(p.lib.api.get_version))),
		RequiredAPIVersion:  ptr.GoString(unsafe.Pointer(C.pl_get_static_str(p.lib.api.get_required_api_version))),
		Name:                ptr.GoString(unsafe.Pointer(C.pl_get_static_str(p.lib.api.get_name))),
		Description:         ptr.GoString(unsafe.Pointer(C.pl_get_static_str(p.lib.api.get_description))),
		EventSource:         ptr.GoString(unsafe.Pointer(C.pl_get_static_str(p.lib.api.anon0.get_event_source))),
		Contact:             ptr.GoString(unsafe.Pointer(C.pl_get_static_str(p.lib.api.get_contact))),
		ID:                  uint32(C.pl_get_static_u32(p.lib.api.anon0.get_id)),
		ExtractEventSources: []string{},
	}
	if p.lib.api.anon1.get_extract_event_sources != nil {
		str := ptr.GoString(unsafe.Pointer(C.pl_get_static_str(p.lib.api.anon1.get_extract_event_sources)))
		if err := json.Unmarshal(([]byte)(str), &p.info.ExtractEventSources); err != nil {
			return nil, err
		}
	}
	if p.lib.api.get_init_schema != nil {
		p.initSchema.Schema = ptr.GoString(unsafe.Pointer(C.pl_get_static_str(p.lib.api.get_init_schema)))
	}

	return p, nil
}

func (p *Plugin) Info() *plugins.Info {
	return &p.info
}

func (p *Plugin) InitSchema() *sdk.SchemaInfo {
	return &p.initSchema
}
