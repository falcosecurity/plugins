package container

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	namespacesapi "github.com/containerd/containerd/api/services/namespaces/v1"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"
)

// An RPC error need not cancel the caller's context. Fail Get deterministically
// at Info (the first Get) or Spec (the second), without relying on timer order.
type interruptedInspection struct {
	deferredContainerService
	mu        sync.Mutex
	namespace string
	failAt    int
	failAfter bool
	calls     int
	code      codes.Code
}

func (s *interruptedInspection) Get(ctx context.Context, req *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	ns, _ := namespaces.Namespace(ctx)
	s.mu.Lock()
	fail := false
	if ns == s.namespace {
		s.calls++
		fail = s.failAt > 0 && (s.calls == s.failAt || (s.failAfter && s.calls > s.failAt))
	}
	s.mu.Unlock()
	if fail {
		return nil, status.Error(s.code, "inspection interrupted before caller cancellation")
	}
	return s.deferredContainerService.Get(ctx, req)
}

func TestContainerdListInspectionRPCError(t *testing.T) {
	for _, phase := range []struct {
		name      string
		get       int
		failAfter bool
	}{{"info", 1, false}, {"spec", 2, false}, {"info_and_spec", 1, true}} {
		for _, code := range []codes.Code{codes.DeadlineExceeded, codes.Canceled, codes.NotFound} {
			for _, namespace := range []string{"alpha", "beta"} {
				t.Run(phase.name+"/"+code.String()+"/"+namespace, func(t *testing.T) {
					service := &interruptedInspection{
						deferredContainerService: deferredContainerService{containers: make(map[string]*containersapi.Container)},
						namespace:                namespace, failAt: phase.get, failAfter: phase.failAfter, code: code,
					}
					for i, ns := range []string{"alpha", "beta"} {
						service.containers[ns] = &containersapi.Container{
							ID:    strings.Repeat(string(rune('a'+i)), 64),
							Image: "alpine:latest", Labels: map[string]string{"namespace": ns},
							Spec: &anypb.Any{TypeUrl: "types.containerd.io/opencontainers/runtime-spec/1/Spec", Value: []byte(`{"process":{"user":{"uid":123}},"linux":{}}`)},
						}
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
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					evts, err := engine.List(ctx)
					require.NoError(t, ctx.Err(), "the RPC error must precede caller cancellation")
					t.Logf("caller error=%v; List error=%v; events=%d", ctx.Err(), err, len(evts))
					for _, evt := range evts {
						t.Logf("id=%s image=%q labels=%v privileged=%v user=%s", evt.ID, evt.Image, evt.Labels, evt.Privileged, evt.User)
					}
					if code == codes.NotFound {
						// Keep the existing best-effort fallback for non-context errors.
						require.NoError(t, err)
						require.Len(t, evts, 2)
						idx := 0
						if namespace == "beta" {
							idx = 1
						}
						require.Equal(t, phase.name == "info", evts[idx].Privileged)
						if phase.get == 1 {
							require.Empty(t, evts[idx].Labels)
						} else {
							require.Equal(t, namespace, evts[idx].Labels["namespace"])
						}
						return
					}
					var incomplete *ListIncompleteError
					require.ErrorAs(t, err, &incomplete)
					cause := context.DeadlineExceeded
					if code == codes.Canceled {
						cause = context.Canceled
					}
					require.ErrorIs(t, err, cause)
					require.Empty(t, incomplete.NotEnumerated)
					wantNamespaces := []string{"alpha", "beta"}
					if namespace == "beta" {
						wantNamespaces = []string{"beta"}
						require.Len(t, evts, 1)
						require.Equal(t, "alpha", evts[0].Labels["namespace"])
						require.True(t, evts[0].Privileged)
					} else {
						require.Empty(t, evts)
					}
					require.Len(t, incomplete.NotInspected, len(wantNamespaces))
					// A deferred lookup first loads the container, then repeats the
					// inspection. Do not publish incomplete metadata as a success.
					service.mu.Lock()
					service.calls = -1 // allow LoadContainer before Info and Spec
					service.mu.Unlock()
					evt, getErr := engine.(*containerdEngine).getInNamespace(ctx, namespace, service.containers[namespace].ID)
					require.ErrorIs(t, getErr, cause)
					require.Nil(t, evt)
					service.mu.Lock()
					service.failAt = 0
					service.mu.Unlock()
					for i, ref := range incomplete.NotInspected {
						require.Equal(t, wantNamespaces[i], ref.Namespace)
						require.Equal(t, service.containers[ref.Namespace].ID, ref.ID)
						// Exercise the same full-ID lookup used by deferred recovery.
						evt, err := engine.(*containerdEngine).getInNamespace(ctx, ref.Namespace, ref.ID)
						require.NoError(t, err)
						require.Equal(t, ref.ID, evt.FullID)
						require.Equal(t, ref.Namespace, evt.Labels["namespace"])
						require.True(t, evt.Privileged)
						require.Equal(t, "123", evt.User)
					}
				})
			}
		}
	}
}
