//go:build linux

package container

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

// TestPodmanDeferredContainersAreLookedUpAfterTheCutListing runs the startup
// of a host whose podman stalls on the first inspection: the listing is cut
// by the engine timeout with every container left over, and the fetcher then
// looks all of them up in the background, with their whole metadata, without
// any request from the plugin.
func TestPodmanDeferredContainersAreLookedUpAfterTheCutListing(t *testing.T) {
	const count = 150
	socket, inspected := newStallingLibpodAPI(t, count, 0)
	engine, err := newPodmanEngine(context.Background(), slog.Default(), socket)
	require.NoError(t, err)

	listCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	evts, err := engine.List(listCtx)
	var incomplete *ListIncompleteError
	require.ErrorAs(t, err, &incomplete)
	assert.Empty(t, evts)
	require.Len(t, incomplete.NotInspected, count)

	fetchCh := make(chan string, 100)
	f := NewFetcherEngine(context.Background(), fetchCh, []Engine{engine}, []DeferredContainers{{Engine: engine, Containers: incomplete.NotInspected}})
	ctx, stop := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	outCh, err := f.Listen(ctx, &wg)
	require.NoError(t, err)
	t.Cleanup(func() {
		stop()
		wg.Wait()
		close(fetchCh)
	})

	recovered := make(map[string]event.Event, count)
	deadline := time.After(10 * time.Second)
	for len(recovered) < count {
		select {
		case evt := <-outCh:
			recovered[evt.ID] = evt
		case <-deadline:
			t.Fatalf("only %d of %d deferred containers were looked up", len(recovered), count)
		}
	}
	for _, ref := range incomplete.NotInspected {
		id := shortContainerID(ref.ID)
		evt, ok := recovered[id]
		require.True(t, ok, "container %s was not looked up", id)
		assert.Equal(t, "healthy-"+id, evt.Name)
		assert.True(t, evt.Privileged)
		assert.Equal(t, map[string]string{"app": "critical"}, evt.Labels)
	}
	// One inspection per container, plus the stalled one of the listing.
	assert.EqualValues(t, count+1, inspected.Load())
}
