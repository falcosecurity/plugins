package container

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
)

// Docker and Podman expose the same event stream format. Keep the inspection
// blocked until the test either allows a response or cancels the listener.
func newListenerAPI(t *testing.T, missing bool) (string, <-chan struct{}, chan<- struct{}, <-chan struct{}) {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "runtime.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	inspecting, release, disconnected := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var inspectOnce sync.Once
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("API-Version", "1.47")
			w.Header().Set("Libpod-API-Version", "6.0.0")
			w.Header().Set("OSType", "linux")
		case strings.HasSuffix(r.URL.Path, "/events"):
			// More than one event exercises a producer delivering the next
			// event while the listener is still inspecting the first one.
			for range 3 {
				_ = json.NewEncoder(w).Encode(map[string]any{"Type": "container", "Action": "create", "Actor": map[string]any{"ID": fakeDockerID(1)}})
			}
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(disconnected)
		case strings.Contains(r.URL.Path, "/containers/") && strings.HasSuffix(r.URL.Path, "/json"):
			inspectOnce.Do(func() { close(inspecting) })
			select {
			case <-r.Context().Done():
				return
			case <-release:
			}
			if missing {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "container already removed"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": fakeDockerID(1), "Name": "/listener-test", "Created": "2026-09-09T00:00:00Z",
				"Image": "sha256:" + strings.Repeat("a", 64), "ImageName": "alpine:latest",
				"Config": map[string]any{"Image": "alpine:latest", "Labels": map[string]string{"app": "test"}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return socket, inspecting, release, disconnected
}

func testHTTPListenerShutdown(t *testing.T, generate engineGenerator, observe func(Engine, chan struct{})) {
	t.Helper()
	for _, tc := range []struct {
		name                                 string
		receive, missing, cancelAfterInspect bool
	}{
		{name: "delivered_metadata", receive: true},
		{name: "delivered_fallback", receive: true, missing: true},
		{name: "cancel_during_inspection"},
		{name: "cancel_after_successful_inspection", cancelAfterInspect: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config.Load(`{"hooks":7}`)
			socket, inspecting, release, disconnected := newListenerAPI(t, tc.missing)
			// The engine context deliberately outlives the listener: a listener
			// must not depend on cancellation of the entire connection.
			engineCtx, stopEngine := context.WithCancel(context.Background())
			defer stopEngine()
			engine, err := generate(engineCtx, slog.Default(), socket)
			require.NoError(t, err)
			inspected := make(chan struct{})
			observe(engine, inspected)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var wg sync.WaitGroup
			out, err := engine.Listen(ctx, &wg)
			require.NoError(t, err)
			t.Cleanup(func() {
				cancel()
				go func() {
					for range out {
					}
				}()
			})
			select {
			case <-inspecting:
			case <-time.After(5 * time.Second):
				t.Fatal("metadata request not started")
			}
			if tc.receive {
				close(release)
				for range 3 {
					evt := waitOnChannelOrTimeout(t, out)
					require.True(t, evt.IsCreate)
					require.Equal(t, fakeDockerID(1), evt.FullID)
					if !tc.missing {
						require.Equal(t, "listener-test", evt.Name)
						require.Equal(t, "test", evt.Labels["app"])
					}
				}
			}
			if tc.cancelAfterInspect {
				close(release)
				select {
				case <-inspected:
				case <-time.After(5 * time.Second):
					t.Fatal("successful inspection not completed")
				}
			}
			cancel()
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("listener did not stop without an event receiver")
			}
			select {
			case <-disconnected:
			case <-time.After(5 * time.Second):
				t.Fatal("event stream still connected after listener stopped")
			}
			require.NoError(t, engineCtx.Err())
		})
	}
}

func TestDockerListenShutdown(t *testing.T) {
	testHTTPListenerShutdown(t, newDockerEngine, func(engine Engine, inspected chan struct{}) {
		dc := engine.(*dockerEngine)
		httpClient := dc.HTTPClient()
		httpClient.Transport = &inspectionTransport{RoundTripper: httpClient.Transport, inspected: inspected}
		require.NoError(t, client.WithHTTPClient(httpClient)(dc.Client))
	})
}

// newRenameAPI serves a Docker Engine API on a unix socket whose event stream
// replays what docker compose does when it recreates a container: it creates
// it under a temporary `<old-id[:12]>_<name>` name, then renames it. A final
// destroy event of another container lets the test check that nothing else
// was sent. Only the events matching the listener filters are sent. Each
// inspection answers the container name current at that point, or fails
// after the rename when renamedMissing is set.
func newRenameAPI(t *testing.T, renamedMissing bool) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "docker.sock")
	listener, err := net.Listen("unix", socket)
	require.NoError(t, err)
	const tmpName, finalName = "/0123456789ab_foo", "/foo"
	var (
		mu        sync.Mutex
		renamed   bool
		inspected = make(chan struct{})
		once      sync.Once
	)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/_ping"):
			w.Header().Set("API-Version", "1.47")
			w.Header().Set("OSType", "linux")
		case strings.HasSuffix(r.URL.Path, "/events"):
			flts, err := filters.FromJSON(r.URL.Query().Get("filters"))
			if !assert.NoError(t, err) {
				return
			}
			enc := json.NewEncoder(w)
			send := func(action, id string, attrs map[string]string) bool {
				if !flts.ExactMatch("event", action) {
					return false
				}
				_ = enc.Encode(map[string]any{"Type": "container", "Action": action, "Actor": map[string]any{"ID": id, "Attributes": attrs}})
				w.(http.Flusher).Flush()
				return true
			}
			if send("create", fakeDockerID(2), map[string]string{"name": strings.TrimPrefix(tmpName, "/")}) {
				// Rename only once the created container has been
				// inspected under its temporary name.
				select {
				case <-inspected:
				case <-r.Context().Done():
					return
				}
			}
			mu.Lock()
			renamed = true
			mu.Unlock()
			send("rename", fakeDockerID(2), map[string]string{"name": strings.TrimPrefix(finalName, "/"), "oldName": tmpName})
			send("destroy", fakeDockerID(1), nil)
			<-r.Context().Done()
		case strings.Contains(r.URL.Path, "/containers/"+fakeDockerID(2)) && strings.HasSuffix(r.URL.Path, "/json"):
			mu.Lock()
			name := tmpName
			if renamed {
				name = finalName
			}
			mu.Unlock()
			defer once.Do(func() { close(inspected) })
			if renamedMissing && name == finalName {
				w.WriteHeader(http.StatusNotFound)
				_ = json.NewEncoder(w).Encode(map[string]string{"message": "container already removed"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": fakeDockerID(2), "Name": name, "Created": "2026-10-28T00:00:00Z",
				"Image":  "sha256:" + strings.Repeat("a", 64),
				"Config": map[string]any{"Image": "alpine:latest", "Labels": map[string]string{"app": "test"}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return socket
}

// The listener must report the name a container gets on rename, whatever
// hooks are attached: with the default `create` hook, docker compose
// recreated containers kept their temporary name otherwise.
func TestDockerListenRename(t *testing.T) {
	// Restore the default hooks of the go-worker tests.
	t.Cleanup(func() { _ = config.Load(`{"hooks":5}`) })
	for _, tc := range []struct {
		name           string
		hooks          string
		renamedMissing bool
	}{
		{name: "create_hook", hooks: `{"hooks":5}`},
		{name: "without_create_hook", hooks: `{"hooks":6}`},
		// A failed inspection on rename must not replace the cached
		// metadata with the minimum set.
		{name: "renamed_container_missing", hooks: `{"hooks":5}`, renamedMissing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, config.Load(tc.hooks))
			socket := newRenameAPI(t, tc.renamedMissing)
			engine, err := newDockerEngine(context.Background(), slog.Default(), socket)
			require.NoError(t, err)
			ctx, cancel := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			defer wg.Wait()
			defer cancel()
			out, err := engine.Listen(ctx, &wg)
			require.NoError(t, err)

			if config.IsHookEnabled(config.HookCreate) {
				evt := waitOnChannelOrTimeout(t, out)
				require.True(t, evt.IsCreate)
				require.Equal(t, fakeDockerID(2), evt.FullID)
				require.Equal(t, "0123456789ab_foo", evt.Name)
			}
			if !tc.renamedMissing {
				evt := waitOnChannelOrTimeout(t, out)
				require.True(t, evt.IsCreate)
				require.Equal(t, fakeDockerID(2), evt.FullID)
				require.Equal(t, "foo", evt.Name)
				require.Equal(t, "test", evt.Labels["app"])
			}
			// The final destroy event comes next: nothing was sent in
			// between.
			evt := waitOnChannelOrTimeout(t, out)
			require.False(t, evt.IsCreate)
			require.Equal(t, fakeDockerID(1), evt.FullID)
		})
	}
}

// The SDK closes an inspection response after parsing it, before returning
// successfully. This lets a test cancel at the successful event-delivery path.
type inspectionTransport struct {
	http.RoundTripper
	inspected chan struct{}
	once      sync.Once
}

func (tr *inspectionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := tr.RoundTripper.RoundTrip(req)
	if err == nil && strings.Contains(req.URL.Path, "/containers/") && strings.HasSuffix(req.URL.Path, "/json") {
		tr.once.Do(func() { resp.Body = &observedResponseBody{ReadCloser: resp.Body, closed: tr.inspected} })
	}
	return resp, err
}

type observedResponseBody struct {
	io.ReadCloser
	closed chan struct{}
	once   sync.Once
}

func (b *observedResponseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(func() { close(b.closed) })
	return err
}
