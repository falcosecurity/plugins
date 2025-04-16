package main

/*
#include <stdbool.h>
typedef const char cchar_t;
typedef void (*async_cb)(const char *json, bool added, bool initial_state);
void makeCallback(const char *json, bool added, bool initial_state, async_cb cb);
*/
import "C"

import (
	"context"
	"encoding/json"
	"github.com/falcosecurity/plugin-sdk-go/pkg/ptr"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/container"
	"runtime"
	"runtime/cgo"
	"sync"
	"unsafe"
)

type PluginCtx struct {
	wg           sync.WaitGroup
	ctxCancel    context.CancelFunc
	stringBuffer ptr.StringBuffer
	pinner       runtime.Pinner
}

//export StartWorker
func StartWorker(cb C.async_cb, initCfg *C.cchar_t, enabledSocks **C.cchar_t) unsafe.Pointer {
	var (
		pluginCtx PluginCtx
		ctx       context.Context
	)
	ctx, pluginCtx.ctxCancel = context.WithCancel(context.Background())

	// See https://github.com/enobufs/go-calls-c-pointer/blob/master/counter_api.go
	goCb := func(containerJson string, added bool, initialState bool) {
		if containerJson == "" {
			return
		}
		// Go cannot call C-function pointers. Instead, use
		// a C-function to have it call the function pointer.
		pluginCtx.stringBuffer.Write(containerJson)
		cadded := C.bool(added)
		cinitialState := C.bool(initialState)
		cStr := (*C.char)(pluginCtx.stringBuffer.CharPtr())
		C.makeCallback(cStr, cadded, cinitialState, cb)
	}

	err := config.Load(ptr.GoString(unsafe.Pointer(initCfg)))
	if err != nil {
		return nil
	}

	generators, err := container.Generators()
	if err != nil {
		return nil
	}

	containerEngines := make([]container.Engine, 0)
	enabledEngines := make(map[string][]string)
	for _, generator := range generators {
		engine, err := generator(ctx)
		if err != nil {
			continue
		}
		containerEngines = append(containerEngines, engine)
		if _, ok := enabledEngines[engine.Name()]; !ok {
			enabledEngines[engine.Name()] = make([]string, 0)
		}
		enabledEngines[engine.Name()] = append(enabledEngines[engine.Name()], engine.Sock())
		// List all pre-existing containers and run `goCb` on all of them
		containers, err := engine.List(ctx)
		if err == nil {
			for _, ctr := range containers {
				goCb(ctr.String(), true, true)
			}
		}
	}
	// Always append the dummy engine that is required to
	// be able to fetch container infos on the fly given other enabled engines.
	containerEngines = append(containerEngines, container.NewFetcherEngine(ctx, containerEngines))

	// Store json of attached sockets in `enabledSocks`
	bytes, _ := json.Marshal(enabledEngines)
	*enabledSocks = C.CString(string(bytes))

	// Start worker goroutine
	pluginCtx.wg.Add(1)
	go func() {
		defer pluginCtx.wg.Done()
		workerLoop(ctx, goCb, containerEngines, &pluginCtx.wg)
	}()
	h := cgo.NewHandle(&pluginCtx)
	pluginCtx.pinner.Pin(&h)
	return unsafe.Pointer(&h)
}

//export StopWorker
func StopWorker(pCtx unsafe.Pointer) {
	h := (*cgo.Handle)(pCtx)
	pluginCtx := h.Value().(*PluginCtx)

	pluginCtx.ctxCancel()
	pluginCtx.wg.Wait()
	pluginCtx.stringBuffer.Free()

	pluginCtx.pinner.Unpin()
	h.Delete()
}

//export AskForContainerInfo
func AskForContainerInfo(containerId *C.cchar_t) {
	containerID := ptr.GoString(unsafe.Pointer(containerId))
	ch := container.GetFetcherChan()
	if ch != nil {
		ch <- containerID
	}
}
