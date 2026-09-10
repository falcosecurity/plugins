package main

/*
#include <stdbool.h>
#include <stdlib.h>
typedef void (*async_cb)(const char *json, bool added, bool initial_state);
extern void makeCallback(const char *json, bool added, bool initial_state, async_cb cb) {
	cb(json, added, initial_state);
}
*/
import "C"

import (
	"context"
	"errors"
	"log/slog"
	"reflect"
	"sync"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/container"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

const ctxDoneIdx = 0

type asyncCb func(string, bool, bool)

// bootstrapEngines creates the engine of each generator and hands the
// containers it already knows about to cb, flagged as initial state.
// StartWorker runs it on the caller's thread, so no runtime socket may stall
// it: each engine gets at most the configured engine timeout to list its
// containers, and one that does not answer in time is logged and left out.
// An engine that answers but does not finish inspecting its containers in
// time is kept: only the containers it did inspect are delivered, the others
// are returned as deferred, for the fetcher to look them up in the background
// once the worker runs. Delivering them with partial metadata would cache that
// metadata for good, since a cached container is never asked again.
// The generators receive the long-lived ctx unbounded on purpose, since an
// engine keeps it for its whole lifetime; they bound their own connection.
func bootstrapEngines(ctx context.Context, generators []container.EngineGenerator, cb asyncCb) ([]container.Engine, map[string][]string, []container.DeferredContainers) {
	engines := make([]container.Engine, 0, len(generators))
	sockets := make(map[string][]string)
	var deferred []container.DeferredContainers
	for _, generator := range generators {
		engine, err := generator(ctx)
		if err != nil {
			// Already logged by the generator.
			continue
		}
		listCtx, cancel := container.WithEngineTimeout(ctx)
		containers, err := engine.List(listCtx)
		timedOut := listCtx.Err() != nil
		cancel()
		logger := slog.With("engine", engine.Name(), "socket", engine.Sock())
		var incomplete *container.ListIncompleteError
		switch {
		case errors.As(err, &incomplete):
			logger.LogAttrs(ctx, slog.LevelWarn, "initial container listing interrupted: unfinished containers and namespaces will be recovered in the background, their events carry no metadata until then",
				slog.Duration("timeout", config.GetEngineTimeout()), slog.Int("inspected", len(containers)), slog.Int("not_inspected", len(incomplete.NotInspected)), slog.Int("namespaces_not_enumerated", len(incomplete.NotEnumerated)))
			deferred = append(deferred, container.DeferredContainers{Engine: engine, Containers: incomplete.NotInspected, Namespaces: incomplete.NotEnumerated})
		case err != nil && timedOut:
			logger.LogAttrs(ctx, slog.LevelWarn, "container engine did not answer within the engine timeout, skipping it for the rest of this run: its containers will have no metadata",
				slog.Duration("timeout", config.GetEngineTimeout()), slog.Any("err", err))
			continue
		case err != nil:
			logger.LogAttrs(ctx, slog.LevelWarn, "cannot list containers", slog.Any("err", err))
		}
		engines = append(engines, engine)
		sockets[engine.Name()] = append(sockets[engine.Name()], engine.Sock())
		// Deliver all pre-existing containers
		for _, ctr := range containers {
			cb(ctr.String(), true, true)
		}
	}
	return engines, sockets, deferred
}

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
		chosen, val, recvOk := reflect.Select(cases)
		if chosen == ctxDoneIdx {
			// ctx.Done!
			return
		}
		if recvOk {
			evt, _ = val.Interface().(event.Event)
			cb(evt.String(), evt.IsCreate, false)
		} else {
			// Remove the stopped goroutine
			cases = append(cases[:chosen], cases[chosen+1:]...)
		}
	}
}
