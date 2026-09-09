package container

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

type deferredNamespaces struct {
	namespacesapi.UnimplementedNamespacesServer
	lists atomic.Int32
}

func (s *deferredNamespaces) List(context.Context, *namespacesapi.ListNamespacesRequest) (*namespacesapi.ListNamespacesResponse, error) {
	s.lists.Add(1)
	return &namespacesapi.ListNamespacesResponse{Namespaces: []*namespacesapi.Namespace{{Name: "alpha"}, {Name: "beta"}}}, nil
}

type deferredContainerService struct {
	containersapi.UnimplementedContainersServer
	mu         sync.Mutex
	containers map[string]*containersapi.Container
	stall      bool
	misses     map[string]int
	wrongIDs   int
}

func (s *deferredContainerService) List(ctx context.Context, _ *containersapi.ListContainersRequest) (*containersapi.ListContainersResponse, error) {
	ns, _ := namespaces.Namespace(ctx)
	return &containersapi.ListContainersResponse{Containers: []*containersapi.Container{s.containers[ns]}}, nil
}

func (s *deferredContainerService) Get(ctx context.Context, req *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	ns, _ := namespaces.Namespace(ctx)
	s.mu.Lock()
	if s.stall {
		s.stall = false
		s.mu.Unlock()
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	}
	defer s.mu.Unlock()
	ctr := s.containers[ns]
	// Containerd Get requires the exact ID within its namespace.
	if ctr == nil || req.ID != ctr.ID {
		s.wrongIDs++
		return nil, status.Error(codes.NotFound, "unknown container")
	}
	if s.misses[ns] > 0 {
		s.misses[ns]--
		return nil, status.Error(codes.NotFound, "container temporarily unavailable")
	}
	return &containersapi.GetContainerResponse{Container: ctr}, nil
}

type unrelatedEngine struct {
	selfEngine
	calls atomic.Int32
}

func (*unrelatedEngine) Name() string { return "unrelated" }

func (e *unrelatedEngine) copy(context.Context) (Engine, error) { return e, nil }

func (e *unrelatedEngine) get(context.Context, string) (*event.Event, error) {
	e.calls.Add(1)
	return nil, nil
}

func TestContainerdDeferredRecovery(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested bool
		retry     bool
	}{{"background", false, false}, {"background_retry", false, true}, {"request_retry", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			socket := filepath.Join(t.TempDir(), "runtime.sock")
			listener, err := net.Listen("unix", socket)
			require.NoError(t, err)
			t.Cleanup(func() { _ = listener.Close() })
			nsService := &deferredNamespaces{}
			ctrService := &deferredContainerService{
				containers: make(map[string]*containersapi.Container), stall: true, misses: make(map[string]int),
			}
			for i, ns := range []string{"alpha", "beta"} {
				ctrService.containers[ns] = &containersapi.Container{
					ID: strings.Repeat(string(rune('a'+i)), 64), Labels: map[string]string{"namespace": ns},
					Spec: &anypb.Any{TypeUrl: "types.containerd.io/opencontainers/runtime-spec/1/Spec", Value: []byte(`{"process":{"user":{"uid":0}},"linux":{}}`)},
				}
			}
			server := grpc.NewServer()
			namespacesapi.RegisterNamespacesServer(server, nsService)
			containersapi.RegisterContainersServer(server, ctrService)
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			engine, err := newContainerdEngine(context.Background(), slog.Default(), socket)
			require.NoError(t, err)
			t.Cleanup(func() { _ = engine.(*containerdEngine).client.Close() })
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			evts, err := engine.List(ctx)
			cancel()
			var incomplete *ListIncompleteError
			require.ErrorAs(t, err, &incomplete)
			require.Empty(t, evts)
			require.Len(t, incomplete.NotInspected, 2)
			for _, ref := range incomplete.NotInspected {
				require.Contains(t, ctrService.containers, ref.Namespace)
				require.Equal(t, ctrService.containers[ref.Namespace].ID, ref.ID)
			}
			if tc.retry {
				ctrService.mu.Lock()
				ctrService.misses["alpha"], ctrService.misses["beta"] = 1, 1
				ctrService.mu.Unlock()
			}
			fetchCh := make(chan string, 100)
			if tc.requested {
				for _, ref := range incomplete.NotInspected {
					// Process requests carry only the cache ID. Duplicate
					// requests must share the pending full-ID lookup.
					fetchCh <- shortContainerID(ref.ID)
					fetchCh <- shortContainerID(ref.ID)
				}
			}
			unrelated := &unrelatedEngine{}
			f := NewFetcherEngine(context.Background(), fetchCh, []Engine{unrelated, engine},
				[]DeferredContainers{{Engine: engine, Containers: incomplete.NotInspected}}).(*fetcher)
			f.retryBackoff = fastBackoff
			for _, g := range f.getters {
				if c, ok := g.(*containerdEngine); ok {
					t.Cleanup(func() { _ = c.client.Close() })
				}
			}
			fetchCtx, stop := context.WithCancel(context.Background())
			var wg sync.WaitGroup
			out, err := f.Listen(fetchCtx, &wg)
			require.NoError(t, err)
			t.Cleanup(func() {
				stop()
				wg.Wait()
				close(fetchCh)
			})
			found := make(map[string]event.Event)
			for len(found) < 2 {
				evt := waitOnChannelOrTimeout(t, out)
				found[evt.ID] = evt
			}
			assertNoEvent(t, out, 20*time.Millisecond)
			for ns, ctr := range ctrService.containers {
				evt := found[shortContainerID(ctr.ID)]
				assert.Equal(t, ctr.ID, evt.FullID)
				assert.Equal(t, ns, evt.Labels["namespace"])
				assert.True(t, evt.Privileged)
			}
			assert.Zero(t, unrelated.calls.Load(), "deferred lookup probed another runtime")
			assert.EqualValues(t, 1, nsService.lists.Load(), "deferred lookup rediscovered known namespaces")
			ctrService.mu.Lock()
			assert.Zero(t, ctrService.wrongIDs)
			ctrService.mu.Unlock()
		})
	}
}
