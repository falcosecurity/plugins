package main

import (
	"context"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/container"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"github.com/stretchr/testify/assert"
	"math"
	"runtime"
	"sync"
	"testing"
	"time"
)

type noopEngine struct {
	exitAfter  time.Duration
	eventAfter time.Duration
}

func (n *noopEngine) Name() string {
	return "noop"
}

func (n *noopEngine) Sock() string {
	panic("implement Sock")
}

func (n *noopEngine) List(_ context.Context) ([]event.Event, error) {
	panic("implement List")
}

func (n *noopEngine) Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error) {
	wg.Add(1)
	out := make(chan event.Event)
	// Random sleep between 5 and 20 ms
	go func() {
		defer wg.Done()
		defer close(out)
		select {
		case <-ctx.Done():
			return
		case <-time.After(n.exitAfter):
			return
		case <-time.After(n.eventAfter):
			out <- event.Event{}
		}
	}()
	return out, nil
}

func TestWorkerLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	numEvents := 0
	// generate some noop containerEngines
	containerEngines := make([]container.Engine, 0)
	for i := 1; i <= 10; i++ {
		// Never leave for timeout
		// Send an event after i ms
		containerEngines = append(containerEngines, &noopEngine{
			exitAfter:  time.Duration(math.MaxInt64),
			eventAfter: time.Duration(i) * time.Millisecond,
		})
	}

	// Start worker goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		workerLoop(ctx, func(jsonEvt string, isCreate bool, _ bool) {
			numEvents++
		}, containerEngines, &wg)
	}()

	// Give some time to gouroutines to generate events
	time.Sleep(20 * time.Millisecond)

	// kill the context
	cancel()

	// Wait on the wg
	wg.Wait()

	// 1 event for each container engine generated
	assert.Equal(t, len(containerEngines), numEvents)
}

func TestWorkerLoopExitBeforeCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	wg := sync.WaitGroup{}
	numEvents := 0
	// generate some noop containerEngines
	containerEngines := make([]container.Engine, 0)
	for i := 15; i <= 25; i++ {
		// Leave after i ms
		// Never send events
		containerEngines = append(containerEngines, &noopEngine{
			exitAfter:  time.Duration(i) * time.Millisecond,
			eventAfter: time.Duration(math.MaxInt64),
		})
	}

	// Start worker goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		workerLoop(ctx, func(jsonEvt string, isCreate bool, _ bool) {
			numEvents++
		}, containerEngines, &wg)
	}()

	// Wait for goroutines to be spawned
	time.Sleep(5 * time.Millisecond)
	numGoroutine := runtime.NumGoroutine()

	// Give some time to gouroutines to do their work
	time.Sleep(20 * time.Millisecond)

	// All worker goroutines left
	// Use LessOrEqual because our own goroutine that runs workerLoop
	// might have already left too!
	assert.LessOrEqual(t, runtime.NumGoroutine(), numGoroutine-10)

	// kill the context
	cancel()

	// Wait on the wg
	wg.Wait()

	// No event sent
	assert.Equal(t, 0, numEvents)
}
