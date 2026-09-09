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

// fakeDockerID returns a 64-character container ID whose short form is i.
func fakeDockerID(i int) string {
	return fmt.Sprintf("%012d", i) + strings.Repeat("0", 52)
}

// newStallingDockerAPI serves a Docker Engine API on a unix socket that lists
// count containers at once, then answers every inspection but the one at
// index stallAt, in request order, which hangs until the request is
// cancelled. It returns the socket path and the count of the inspection
// requests received.
func newStallingDockerAPI(t *testing.T, count, stallAt int) (string, *atomic.Int32) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	imageID := "sha256:" + strings.Repeat("a", 64)
	var inspected atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("API-Version", "1.47")
			w.Header().Set("OSType", "linux")
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/containers/json"):
			ctrs := make([]map[string]any, count)
			for i := range ctrs {
				ctrs[i] = map[string]any{"Id": fakeDockerID(i + 1), "Image": "alpine:latest", "ImageID": imageID, "Created": 1757376000}
			}
			_ = json.NewEncoder(w).Encode(ctrs)
		case strings.Contains(r.URL.Path, "/images/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"Id": imageID, "RepoTags": []string{"alpine:latest"}, "RepoDigests": []string{"alpine@sha256:" + strings.Repeat("b", 64)}})
		default: // .../containers/{id}/json
			if int(inspected.Add(1)) == stallAt+1 {
				<-r.Context().Done()
				return
			}
			parts := strings.Split(r.URL.Path, "/")
			id := parts[len(parts)-2]
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": id, "Name": "/healthy-" + shortContainerID(id), "Created": "2026-09-09T00:00:00Z", "Image": imageID,
				"HostConfig": map[string]any{"Privileged": true},
				"Config":     map[string]any{"Image": "alpine:latest", "Labels": map[string]string{"app": "critical"}},
			})
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return socket, &inspected
}

func TestDockerListStopsInspectingOnceTheContextIsDone(t *testing.T) {
	// Six containers, the third inspection never answers: with a 200ms
	// deadline the listing returns the two containers inspected so far, with
	// their whole metadata, and leaves the other four to their first event.
	socket, inspected := newStallingDockerAPI(t, 6, 2)
	engine, err := newDockerEngine(context.Background(), slog.Default(), socket)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	evts, err := engine.List(ctx)
	elapsed := time.Since(start)

	var incomplete *ListIncompleteError
	require.ErrorAs(t, err, &incomplete)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	// The containers left are reported, by short ID, for the background lookups.
	assert.Equal(t, []string{"000000000003", "000000000004", "000000000005", "000000000006"}, incomplete.NotInspected)
	require.Len(t, evts, 2)
	for i, evt := range evts {
		assert.Equal(t, shortContainerID(fakeDockerID(i+1)), evt.ID)
		assert.Equal(t, "healthy-"+evt.ID, evt.Name)
		assert.True(t, evt.Privileged)
		assert.Equal(t, map[string]string{"app": "critical"}, evt.Labels)
	}
	// The containers left are not inspected at all.
	assert.EqualValues(t, 3, inspected.Load())
	assert.Less(t, elapsed, time.Second)
}
