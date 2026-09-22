package container

import (
	"context"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	ctEvents "github.com/containerd/containerd/api/events"
	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	eventsapi "github.com/containerd/containerd/api/services/events/v1"
	typesapi "github.com/containerd/containerd/api/types"
	"github.com/containerd/typeurl/v2"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type shutdownEventService struct {
	eventsapi.UnimplementedEventsServer
}

func (*shutdownEventService) Subscribe(_ *eventsapi.SubscribeRequest, stream eventsapi.Events_SubscribeServer) error {
	evt, err := typeurl.MarshalAnyToProto(&ctEvents.ContainerCreate{ID: strings.Repeat("a", 64), Image: "alpine:latest"})
	if err != nil {
		return err
	}
	if err := stream.Send(&typesapi.Envelope{Namespace: "k8s.io", Topic: "/containers/create", Event: evt}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}

type shutdownContainerService struct {
	containersapi.UnimplementedContainersServer
	inspecting chan struct{}
	release    chan struct{}
}

func (s *shutdownContainerService) Get(ctx context.Context, _ *containersapi.GetContainerRequest) (*containersapi.GetContainerResponse, error) {
	close(s.inspecting)
	select {
	case <-ctx.Done():
		return nil, status.FromContextError(ctx.Err()).Err()
	case <-s.release:
		return nil, status.Error(codes.NotFound, "container already removed")
	}
}

func TestContainerdListenShutdown(t *testing.T) {
	for _, receive := range []bool{true, false} {
		name := "cancel_during_inspection"
		if receive {
			name = "delivered_fallback"
		}
		t.Run(name, func(t *testing.T) {
			s := &shutdownContainerService{inspecting: make(chan struct{}), release: make(chan struct{})}
			socket := filepath.Join(t.TempDir(), "runtime.sock")
			listener, err := net.Listen("unix", socket)
			require.NoError(t, err)
			server := grpc.NewServer()
			containersapi.RegisterContainersServer(server, s)
			eventsapi.RegisterEventsServer(server, &shutdownEventService{})
			go func() { _ = server.Serve(listener) }()
			t.Cleanup(server.Stop)
			engine, err := newContainerdEngine(context.Background(), slog.Default(), socket)
			require.NoError(t, err)
			t.Cleanup(func() { _ = engine.(*containerdEngine).client.Close() })
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
			case <-s.inspecting:
			case <-time.After(5 * time.Second):
				t.Fatal("metadata request not started")
			}
			if receive {
				close(s.release)
				evt := waitOnChannelOrTimeout(t, out)
				require.True(t, evt.IsCreate)
				require.Equal(t, strings.Repeat("a", 64), evt.FullID)
				require.Equal(t, "alpine:latest", evt.Image)
			}
			cancel()
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("listener did not stop without an event receiver")
			}
		})
	}
}
