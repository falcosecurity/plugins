package container

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

// slowEnumeration stalls the first listing of one namespace, then fails a
// configurable number of attempts before recovering. Get requires full IDs,
// as containerd does; process requests alone cannot recover these containers.
type slowEnumeration struct {
	containersapi.UnimplementedContainersServer
	containers map[string][]*containersapi.Container
	stall      string
	failures   int
	rpcError   codes.Code
	mu         sync.Mutex
	calls      map[string]int
}

func (s *slowEnumeration) List(ctx context.Context, _ *containersapi.ListContainersRequest) (*containersapi.ListContainersResponse, error) {
	ns, _ := namespaces.Namespace(ctx)
	s.mu.Lock()
	s.calls[ns]++
	attempt := s.calls[ns]
	s.mu.Unlock()
	if ns == s.stall {
		if attempt == 1 {
			if s.rpcError != codes.OK {
				return nil, status.Error(s.rpcError, "listing interrupted by the runtime")
			}
			<-ctx.Done()
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		if attempt <= s.failures+1 {
			return nil, status.Error(codes.Unavailable, "runtime still recovering")
		}
	}
	return &containersapi.ListContainersResponse{Containers: s.containers[ns]}, nil
}

func (s *slowEnumeration) Get(ctx context.Context, req *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	ns, _ := namespaces.Namespace(ctx)
	for _, ctr := range s.containers[ns] {
		if req.ID == ctr.ID {
			return &containersapi.GetContainerResponse{Container: ctr}, nil
		}
	}
	return nil, status.Error(codes.NotFound, "exact container ID required")
}

func TestContainerdRecoversUnenumeratedNamespaces(t *testing.T) {
	for _, tc := range []struct {
		name, stall string
		requests    bool
		failures    int
		rpcError    codes.Code
	}{
		{name: "first_namespace", stall: "alpha"},
		{name: "later_namespace", stall: "beta"},
		{name: "saturated_requests", stall: "beta", requests: true},
		{name: "namespace_retries_outlive_container_backoff", stall: "alpha", failures: 5},
		{name: "rpc_deadline_before_context", stall: "alpha", rpcError: codes.DeadlineExceeded},
		{name: "rpc_cancellation_before_context", stall: "beta", rpcError: codes.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service := &slowEnumeration{
				containers: make(map[string][]*containersapi.Container), calls: make(map[string]int),
				stall: tc.stall, failures: tc.failures, rpcError: tc.rpcError,
			}
			const total = 151 // more than the process request channel can hold
			for i := 0; i < total; i++ {
				ns := "beta"
				if i == 0 {
					ns = "alpha"
				}
				service.containers[ns] = append(service.containers[ns], &containersapi.Container{
					ID: fmt.Sprintf("%012x", i) + strings.Repeat("a", 52), Image: "alpine:latest",
					Labels: map[string]string{"namespace": ns},
					Spec:   &anypb.Any{TypeUrl: "types.containerd.io/opencontainers/runtime-spec/1/Spec", Value: []byte(`{"process":{"user":{"uid":0}},"linux":{}}`)},
				})
			}
			socket := filepath.Join(t.TempDir(), "runtime.sock")
			listener, err := net.Listen("unix", socket)
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			server := grpc.NewServer()
			namespacesapi.RegisterNamespacesServer(server, &deferredNamespaces{})
			containersapi.RegisterContainersServer(server, service)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			engine, err := newContainerdEngine(context.Background(), slog.Default(), socket)
			require.NoError(t, err)
			t.Cleanup(func() { _ = engine.(*containerdEngine).client.Close() })

			timeout := 50 * time.Millisecond
			if tc.rpcError != codes.OK {
				timeout = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			evts, err := engine.List(ctx)
			if tc.rpcError != codes.OK {
				require.NoError(t, ctx.Err(), "the RPC error must be handled before caller cancellation")
			}
			cancel()
			require.Empty(t, evts)
			var incomplete *ListIncompleteError
			require.ErrorAs(t, err, &incomplete)
			if tc.stall == "alpha" {
				assert.Empty(t, incomplete.NotInspected)
				assert.Equal(t, []string{"alpha", "beta"}, incomplete.NotEnumerated)
			} else {
				require.Len(t, incomplete.NotInspected, 1)
				assert.Equal(t, []string{"beta"}, incomplete.NotEnumerated)
			}

			fetchCh := make(chan string, 100)
			if tc.requests {
				refused := 0
				for _, ctrs := range service.containers {
					for _, ctr := range ctrs {
						select {
						case fetchCh <- shortContainerID(ctr.ID):
						default:
							refused++
						}
					}
				}
				assert.Equal(t, total-cap(fetchCh), refused)
			}
			f := NewFetcherEngine(context.Background(), fetchCh, []Engine{engine}, []DeferredContainers{{
				Engine: engine, Containers: incomplete.NotInspected, Namespaces: incomplete.NotEnumerated,
			}}).(*fetcher)
			f.retryBackoff = []time.Duration{2 * time.Millisecond, 4 * time.Millisecond}
			for _, g := range f.getters {
				c := g.(*containerdEngine)
				t.Cleanup(func() { _ = c.client.Close() })
			}
			fetchCtx, stop := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			out, err := f.Listen(fetchCtx, &wg)
			require.NoError(t, err)
			t.Cleanup(func() { stop(); wg.Wait(); close(fetchCh) })
			found := make(map[string]event.Event)
			deadline := time.After(5 * time.Second)
			for len(found) < total {
				select {
				case evt := <-out:
					found[evt.ID] = evt
				case <-deadline:
					t.Fatalf("recovered %d of %d containers", len(found), total)
				}
			}
			for ns, ctrs := range service.containers {
				for _, ctr := range ctrs {
					evt := found[shortContainerID(ctr.ID)]
					assert.Equal(t, ctr.ID, evt.FullID)
					assert.Equal(t, ctr.Image, evt.Image)
					assert.Equal(t, ns, evt.Labels["namespace"])
				}
			}
			assertNoEvent(t, out, 20*time.Millisecond)
			service.mu.Lock()
			assert.Equal(t, tc.failures+2, service.calls[tc.stall])
			service.mu.Unlock()
		})
	}
}
