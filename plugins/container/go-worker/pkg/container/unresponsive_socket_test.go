package container

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
)

// newUnresponsiveSocket starts a unix socket that accepts connections and
// never answers them, like a socket-activated runtime whose service is gone
// (falcosecurity/plugins#1487). It returns the socket path.
func newUnresponsiveSocket(t *testing.T) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, conn)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, conn := range conns {
			_ = conn.Close()
		}
	})
	return socket
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

func TestDockerListHonoursContextOnUnresponsiveSocket(t *testing.T) {
	socket := newUnresponsiveSocket(t)
	engine, err := newDockerEngine(context.Background(), slog.Default(), socket)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = engine.List(ctx)
	assert.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}

func TestContainerdListHonoursContextOnUnresponsiveSocket(t *testing.T) {
	socket := newUnresponsiveSocket(t)
	engine, err := newContainerdEngine(context.Background(), slog.Default(), socket)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = engine.List(ctx)
	assert.Error(t, err)
	assert.Less(t, time.Since(start), 5*time.Second)
}
