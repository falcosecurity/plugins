//go:build linux

package container

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
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
