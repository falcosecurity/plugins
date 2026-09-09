//go:build linux

package container

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPodmanEngineGivesUpOnUnresponsiveSocket(t *testing.T) {
	setEngineTimeout(t, 1)
	socket := newUnresponsiveSocket(t)

	start := time.Now()
	_, err := newPodmanEngine(context.Background(), slog.Default(), socket)
	elapsed := time.Since(start)

	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	// The bindings retry a failed request 3 times, sleeping in between.
	assert.GreaterOrEqual(t, elapsed, time.Second)
	assert.Less(t, elapsed, 5*time.Second)
}

func TestPodmanListHonoursContext(t *testing.T) {
	// A libpod API that answers the ping and then never answers anything else.
	socket := filepath.Join(t.TempDir(), "podman.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/_ping") {
			w.Header().Set("Libpod-API-Version", "6.0.0")
			w.WriteHeader(http.StatusOK)
			return
		}
		<-r.Context().Done()
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	engine, err := newPodmanEngine(context.Background(), slog.Default(), socket)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = engine.List(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)

	// The connection context of the engine is untouched by the bounded call.
	assert.NoError(t, engine.(*podmanEngine).pCtx.Err())
}

// newStallingLibpodAPI serves a libpod API on a unix socket that answers the
// ping and lists count containers at once, then answers every inspection but
// the one at index stallAt, in request order, which hangs until the request
// is cancelled. It returns the socket path and the count of the inspection
// requests received.
func newStallingLibpodAPI(t *testing.T, count, stallAt int) (string, *atomic.Int32) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "podman.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	var inspected atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("Libpod-API-Version", "6.0.0")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			ctrs := make([]map[string]any, count)
			for i := range ctrs {
				ctrs[i] = map[string]any{"Id": fmt.Sprintf("%012d", i+1), "Image": "alpine:latest", "Created": "2026-09-09T00:00:00Z"}
			}
			_ = json.NewEncoder(w).Encode(ctrs)
		default: // .../containers/{id}/json
			if int(inspected.Add(1)) == stallAt+1 {
				<-r.Context().Done()
				return
			}
			parts := strings.Split(r.URL.Path, "/")
			id := parts[len(parts)-2]
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": id, "Name": "healthy-" + id, "ImageName": "alpine:latest", "Created": "2026-09-09T00:00:00Z",
				"HostConfig": map[string]any{"Privileged": true},
				"Config":     map[string]any{"Labels": map[string]string{"app": "critical"}},
			})
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return socket, &inspected
}

func TestPodmanListStopsInspectingOnceTheContextIsDone(t *testing.T) {
	// Six containers, the third inspection never answers: with a 200ms
	// deadline the listing returns the two containers inspected so far, with
	// their whole metadata, and leaves the other four to their first event.
	socket, inspected := newStallingLibpodAPI(t, 6, 2)
	engine, err := newPodmanEngine(context.Background(), slog.Default(), socket)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	evts, err := engine.List(ctx)
	elapsed := time.Since(start)

	var incomplete *ListIncompleteError
	require.ErrorAs(t, err, &incomplete)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	// The containers left are reported for the background lookups.
	assert.Equal(t, []string{"000000000003", "000000000004", "000000000005", "000000000006"}, incomplete.NotInspected)
	require.Len(t, evts, 2)
	for i, evt := range evts {
		assert.Equal(t, fmt.Sprintf("%012d", i+1), evt.ID)
		assert.Equal(t, "healthy-"+evt.ID, evt.Name)
		assert.True(t, evt.Privileged)
		assert.Equal(t, map[string]string{"app": "critical"}, evt.Labels)
	}
	// The containers left are not inspected at all: the stalled inspection is
	// the only one to pay the three attempts and the pauses of the podman
	// client (100, 200 and 300ms) once cancelled.
	assert.EqualValues(t, 3, inspected.Load())
	assert.Less(t, elapsed, 1500*time.Millisecond)
	assert.NoError(t, engine.(*podmanEngine).pCtx.Err())
}
