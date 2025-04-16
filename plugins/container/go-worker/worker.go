package main

/*
#include <stdbool.h>
#include <stdlib.h>
typedef void (*async_cb)(const char *json, bool added);
extern void makeCallback(const char *json, bool added, async_cb cb) {
	cb(json, added);
}
*/
import "C"

import (
	"context"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/container"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"reflect"
	"sync"
)

const ctxDoneIdx = 0

type asyncCb func(string, bool)

func workerLoop(ctx context.Context, cb asyncCb, containerEngines []container.Engine, wg *sync.WaitGroup) {
	var evt event.Event

	// We need to use a reflect.SelectCase here since
	// we will need to select a variable number of channels
	cases := make([]reflect.SelectCase, 0)

	// Emplace back case for `ctx.Done` channel
	cases = append(cases, reflect.SelectCase{
		Dir:  reflect.SelectRecv,
		Chan: reflect.ValueOf(ctx.Done()),
	})

	// Emplace back cases for each container engine listener
	for _, engine := range containerEngines {
		ch, err := engine.Listen(ctx, wg)
		if err != nil {
			continue
		}
		cases = append(cases, reflect.SelectCase{
			Dir:  reflect.SelectRecv,
			Chan: reflect.ValueOf(ch),
		})
	}

	for {
		chosen, val, _ := reflect.Select(cases)
		if chosen == ctxDoneIdx {
			// ctx.Done!
			break
		} else {
			evt, _ = val.Interface().(event.Event)
			cb(evt.String(), evt.IsCreate)
		}
	}
}
