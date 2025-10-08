package main

import (
	"context"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/container"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"github.com/stretchr/testify/assert"
	"math"
	"sync"
	"testing"
	"time"
)

type noopEngine struct {
	exitAfter  time.Duration
	eventAfter time.Duration
	// listeningWaitGroup is used to signal that the noopEngine.Listen internal goroutine terminated its execution.
	listeningWaitGroup *sync.WaitGroup
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
		defer n.listeningWaitGroup.Done()
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
	defer cancel()

	numEvents := 0
	// generate some noop containerEngines
	containerEngines := make([]container.Engine, 0, 10)
	// listeningWaitGroup accounts for noop engines' internal listening goroutines.
	listeningWaitGroup := &sync.WaitGroup{}
	listeningWaitGroup.Add(10)
	for i := 1; i <= 10; i++ {
		// Never leave for timeout
		// Send an event after i ms
		containerEngines = append(containerEngines, &noopEngine{
			exitAfter:          time.Duration(math.MaxInt64),
			eventAfter:         time.Duration(i) * time.Millisecond,
			listeningWaitGroup: listeningWaitGroup,
		})
	}

	// Signal that all noop engines' have produced a value.
	signalCh := make(chan struct{})

	// Start worker goroutine
	// globalWaitGroup accounts for both workerLoop and noop engines' internal listening goroutines.
	globalWaitGroup := &sync.WaitGroup{}
	globalWaitGroup.Add(1)
	go func() {
		defer globalWaitGroup.Done()
		workerLoop(ctx, func(jsonEvt string, isCreate bool, _ bool) {
			numEvents++
			if numEvents == 10 {
				// This will only be executed once, because each noop engine produce just 1 event.
				close(signalCh)
			}
		}, containerEngines, globalWaitGroup)
	}()

	select {
	case <-ctx.Done():
		t.Fatal("Context canceled before all container engine listening goroutines have produced an event")
	case <-signalCh:
		assert.Equal(t, len(containerEngines), numEvents)
	}
}

func TestWorkerLoopExitBeforeCtxCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	numEvents := 0
	// generate some noop containerEngines
	containerEngines := make([]container.Engine, 0, 10)
	// listeningWaitGroup accounts for noop engines' internal listening goroutines.
	listeningWaitGroup := &sync.WaitGroup{}
	listeningWaitGroup.Add(10)
	for i := 15; i < 25; i++ {
		// Leave after i ms
		// Never send events
		containerEngines = append(containerEngines, &noopEngine{
			exitAfter:          time.Duration(i) * time.Millisecond,
			eventAfter:         time.Duration(math.MaxInt64),
			listeningWaitGroup: listeningWaitGroup,
		})
	}

	// Start worker goroutine
	// globalWaitGroup accounts for both workerLoop and noop engines' internal listening goroutines.
	globalWaitGroup := &sync.WaitGroup{}
	globalWaitGroup.Add(1)
	go func() {
		defer globalWaitGroup.Done()
		workerLoop(ctx, func(jsonEvt string, isCreate bool, _ bool) {
			numEvents++
		}, containerEngines, globalWaitGroup)
	}()

	// Signal that all noop engines' internal listening goroutines terminated.
	signalCh := make(chan struct{})
	go func() {
		defer close(signalCh)
		listeningWaitGroup.Wait()
	}()

	select {
	case <-ctx.Done():
		t.Fatal("Context canceled before all container engine listening goroutines terminated")
	case <-signalCh:
		cancel()
		globalWaitGroup.Wait()
		assert.Equal(t, 0, numEvents)
	}
}
