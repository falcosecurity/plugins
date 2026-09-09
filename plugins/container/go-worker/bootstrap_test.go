package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/container"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

// listEngine is an Engine whose List returns canned events or an error, or
// blocks until the context is done when unresponsive.
type listEngine struct {
	name, socket string
	events       []event.Event
	err          error
	unresponsive bool
}

func (e *listEngine) Name() string { return e.name }

func (e *listEngine) Sock() string { return e.socket }

func (e *listEngine) List(ctx context.Context) ([]event.Event, error) {
	if e.unresponsive {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return e.events, e.err
}

func (e *listEngine) Listen(context.Context, *sync.WaitGroup) (<-chan event.Event, error) {
	return nil, errors.New("not implemented")
}

func generatorOf(engine container.Engine) container.EngineGenerator {
	return func(context.Context) (container.Engine, error) { return engine, nil }
}

// setEngineTimeout sets the engine timeout, in seconds, for the test duration.
func setEngineTimeout(t *testing.T, seconds int) {
	t.Helper()
	previous := config.Get().EngineTimeout
	require.NoError(t, config.Load(fmt.Sprintf(`{"engine_timeout": %d}`, seconds)))
	t.Cleanup(func() {
		require.NoError(t, config.Load(fmt.Sprintf(`{"engine_timeout": %d}`, previous)))
	})
}

func TestBootstrapEnginesSkipsUnresponsiveEngine(t *testing.T) {
	setEngineTimeout(t, 1)

	unresponsive := &listEngine{name: "podman", socket: "/run/podman/podman.sock", unresponsive: true}
	healthy := &listEngine{name: "docker", socket: "/var/run/docker.sock", events: []event.Event{
		{Info: event.Info{Container: event.Container{ID: "abc123abc123"}}, IsCreate: true},
		{Info: event.Info{Container: event.Container{ID: "def456def456"}}, IsCreate: true},
	}}
	generators := []container.EngineGenerator{
		generatorOf(unresponsive),
		func(context.Context) (container.Engine, error) { return nil, errors.New("connection refused") },
		generatorOf(healthy),
	}

	var delivered []string
	start := time.Now()
	engines, sockets := bootstrapEngines(context.Background(), generators, func(json string, added, initialState bool) {
		assert.True(t, added)
		assert.True(t, initialState)
		delivered = append(delivered, json)
	})
	elapsed := time.Since(start)

	// The unresponsive engine is given up after the engine timeout, not before.
	assert.GreaterOrEqual(t, elapsed, time.Second)
	assert.Less(t, elapsed, 5*time.Second)
	assert.Equal(t, []container.Engine{healthy}, engines)
	assert.Equal(t, map[string][]string{"docker": {"/var/run/docker.sock"}}, sockets)
	assert.Len(t, delivered, 2)
}

func TestBootstrapEnginesKeepsEngineFailingToList(t *testing.T) {
	failing := &listEngine{name: "containerd", socket: "/run/containerd/containerd.sock", err: errors.New("permission denied")}

	delivered := 0
	engines, sockets := bootstrapEngines(context.Background(), []container.EngineGenerator{generatorOf(failing)}, func(string, bool, bool) {
		delivered++
	})

	assert.Equal(t, []container.Engine{failing}, engines)
	assert.Equal(t, map[string][]string{"containerd": {"/run/containerd/containerd.sock"}}, sockets)
	assert.Zero(t, delivered)
}
