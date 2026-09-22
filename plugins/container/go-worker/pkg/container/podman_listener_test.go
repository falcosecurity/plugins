//go:build linux

package container

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.podman.io/podman/v6/pkg/bindings"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
)

func TestPodmanListenShutdown(t *testing.T) {
	testHTTPListenerShutdown(t, newPodmanEngine, func(engine Engine, inspected chan struct{}) {
		connection, err := bindings.GetClient(engine.(*podmanEngine).pCtx)
		require.NoError(t, err)
		connection.Client.Transport = &inspectionTransport{RoundTripper: connection.Client.Transport, inspected: inspected}
	})
}

type eventTransport struct {
	http.RoundTripper
	body io.ReadCloser
}

func (tr eventTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Path, "/events") {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: tr.body, Request: req}, nil
	}
	return tr.RoundTripper.RoundTrip(req)
}

func TestPodmanListenDrainsPendingSourceEvent(t *testing.T) {
	config.Load(`{"hooks":7}`)
	socket, inspecting, _, _ := newListenerAPI(t, false)
	engineCtx, stopEngine := context.WithCancel(context.Background())
	defer stopEngine()
	engine, err := newPodmanEngine(engineCtx, slog.Default(), socket)
	require.NoError(t, err)
	connection, err := bindings.GetClient(engine.(*podmanEngine).pCtx)
	require.NoError(t, err)
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	body := &observedResponseBody{ReadCloser: reader, closed: make(chan struct{})}
	connection.Client.Transport = eventTransport{RoundTripper: connection.Client.Transport, body: body}
	secondRead := make(chan struct{})
	go func() {
		defer writer.Close()
		for range 2 {
			if _, err := fmt.Fprintf(writer, `{"Type":"container","Action":"create","Actor":{"ID":%q}}`+"\n", fakeDockerID(1)); err != nil {
				return
			}
		}
		// io.Pipe.Write returns only after the decoder read the bytes. The
		// SDK now has an event to send even if its context is cancelled.
		close(secondRead)
	}()
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
	select {
	case <-secondRead:
	case <-time.After(5 * time.Second):
		t.Fatal("second source event not read")
	}
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not stop")
	}
	// Only Events' deferred cleanup calls this Close. Merely cancelling an
	// HTTP request would not prove its channel sender has returned.
	select {
	case <-body.closed:
	case <-time.After(5 * time.Second):
		t.Fatal("SDK producer stranded after listener stopped")
	}
}
