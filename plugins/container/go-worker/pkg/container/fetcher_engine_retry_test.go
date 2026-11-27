package container

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

// listGetter is an Engine that also answers single-container lookups. Its
// List blocks until release when slow, then returns the given containers,
// mimicking a runtime that hangs on its first listing and answers later.
type listGetter struct {
	name, socket string
	// release, when non-nil, must be closed before List answers.
	release chan struct{}
	// listErr, when non-nil, is returned by List once released.
	listErr error
	// events are returned by a successful List.
	events []event.Event
	// notInspected, when set, makes List return the events with a
	// ListIncompleteError for these containers once released.
	notInspected []ContainerRef

	mu       sync.Mutex
	attempts int
	lookups  map[string]int
}

func newListGetter(name string) *listGetter {
	return &listGetter{name: name, lookups: make(map[string]int)}
}

func (e *listGetter) Name() string { return e.name }
func (e *listGetter) Sock() string { return e.socket }

func (e *listGetter) List(ctx context.Context) ([]event.Event, error) {
	e.mu.Lock()
	e.attempts++
	e.mu.Unlock()
	if e.release != nil {
		select {
		case <-e.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if e.listErr != nil {
		return nil, e.listErr
	}
	if len(e.notInspected) > 0 {
		return e.events, &ListIncompleteError{NotInspected: e.notInspected, Err: errors.New("interrupted")}
	}
	return e.events, nil
}

func (e *listGetter) Listen(context.Context, *sync.WaitGroup) (<-chan event.Event, error) {
	return nil, errors.New("not implemented")
}

func (e *listGetter) get(_ context.Context, containerId string) (*event.Event, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.lookups[containerId]++
	return &event.Event{Info: event.Info{Container: event.Container{ID: containerId}}, IsCreate: true}, nil
}

func (e *listGetter) lists() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.attempts
}

func (e *listGetter) count(containerId string) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lookups[containerId]
}

func (e *listGetter) copy(context.Context) (Engine, error) { return e, nil }

// TestFetcherRecoversAnEngineDroppedAtStartup covers the follow-up of #1535:
// an engine whose initial listing timed out used to be dropped for the
// lifetime of the plugin, so its containers were never published and never
// looked up. It is retried in the background instead: when its listing
// answers, its containers are published and it takes part in the lookups.
func TestFetcherRecoversAnEngineDroppedAtStartup(t *testing.T) {
	setEngineTimeout(t, 1)
	stalled := newListGetter("docker")
	stalled.socket = "/var/run/docker.sock"
	stalled.release = make(chan struct{})
	stalled.events = []event.Event{
		{Info: event.Info{Container: event.Container{ID: "aaaabbbbcccc"}}, IsCreate: true},
		{Info: event.Info{Container: event.Container{ID: "ddddeeeeffff"}}, IsCreate: true},
	}
	// The engine never finished its startup listing in time.
	fetchCh := make(chan string)
	f := NewFetcherEngine(context.Background(), fetchCh, nil, []DeferredContainers{{Engine: stalled, RetryList: true}}).(*fetcher)
	require.Empty(t, f.getters, "a dropped engine must take part in no lookup before its listing answers")

	outCh := runFetcher(t, f)

	// While the listing is stalled, a request misses: the engine is not probed.
	fetchCh <- "aaaabbbbcccc"
	assertNoEvent(t, outCh, sumDurations(fastBackoff))
	assert.Zero(t, stalled.count("aaaabbbbcccc"))
	// The background listing attempt is under way, held by the runtime.
	assert.Eventually(t, func() bool { return stalled.lists() >= 1 }, time.Second, 5*time.Millisecond)

	// The runtime unstalls: the stalled attempt answers, the containers are
	// published and the engine joins the lookups.
	close(stalled.release)
	ids := make(map[string]bool)
	deadline := time.After(5 * time.Second)
	for len(ids) < 2 {
		select {
		case evt := <-outCh:
			ids[evt.ID] = true
		case <-deadline:
			t.Fatalf("the recovered listing published %d containers, want 2", len(ids))
		}
	}
	assert.Equal(t, 1, stalled.lists(), "one listing attempt, held by the runtime, answered")

	// The engine now serves on-demand lookups too.
	fetchCh <- "0123456789ab"
	evt := waitOnChannelOrTimeout(t, outCh)
	assert.Equal(t, "0123456789ab", evt.ID)
	assert.Equal(t, 1, stalled.count("0123456789ab"))
	assertNoEvent(t, outCh, 50*time.Millisecond)
}

// TestFetcherDroppedEngineListingRetryIsBounded checks that each background
// listing retry of a dropped engine is bounded by the engine timeout and
// keeps being retried, instead of blocking the serving goroutine for good.
func TestFetcherDroppedEngineListingRetryIsBounded(t *testing.T) {
	setEngineTimeout(t, 1)
	stalled := newListGetter("podman")
	stalled.socket = "/run/podman/podman.sock"
	stalled.release = make(chan struct{}) // never closed: every listing hangs

	fetchCh := make(chan string)
	f := NewFetcherEngine(context.Background(), fetchCh, nil, []DeferredContainers{{Engine: stalled, RetryList: true}}).(*fetcher)
	outCh := runFetcher(t, f)

	// The fetcher keeps serving while the engine listing keeps timing out:
	// requests are still answered by the other getters... there are none, so
	// the request misses; what matters is that the goroutine is not stuck on
	// the stalled listing.
	fetchCh <- "anycontainer"
	assertNoEvent(t, outCh, 2*sumDurations(fastBackoff))
	assert.Zero(t, stalled.count("anycontainer"))
	// The stalled engine answered the ping but no listing: it is retried at
	// the final backoff delay. Two bounded attempts take about twice the
	// engine timeout.
	assert.Eventually(t, func() bool { return stalled.lists() >= 2 }, 4*time.Second, 20*time.Millisecond)
}

// TestFetcherDroppedEnginePartialListing checks that a recovered engine whose
// listing is interrupted partway behaves like a partial startup listing: the
// inspected containers are published, the rest is looked up in the background.
func TestFetcherDroppedEnginePartialListing(t *testing.T) {
	stalled := newListGetter("containerd")
	stalled.socket = "/run/containerd/containerd.sock"
	stalled.events = []event.Event{
		{Info: event.Info{Container: event.Container{ID: "aaaabbbbcccc"}}, IsCreate: true},
	}
	stalled.notInspected = []ContainerRef{{ID: "dddddddddddd"}}

	fetchCh := make(chan string)
	f := NewFetcherEngine(context.Background(), fetchCh, nil, []DeferredContainers{{Engine: stalled, RetryList: true}}).(*fetcher)
	outCh := runFetcher(t, f)

	evt := waitOnChannelOrTimeout(t, outCh)
	assert.Equal(t, "aaaabbbbcccc", evt.ID)
	// The not-inspected container is looked up through the engine once it
	// joined the getters.
	evt = waitOnChannelOrTimeout(t, outCh)
	assert.Equal(t, "dddddddddddd", evt.ID)
	assert.GreaterOrEqual(t, stalled.count("dddddddddddd"), 1)
	assertNoEvent(t, outCh, 50*time.Millisecond)
}

// TestNewFetcherEngineKeepsDroppedEngineCopy verifies the constructor wiring:
// a RetryList group stores a copy of the engine and no lookup getter.
func TestNewFetcherEngineKeepsDroppedEngineCopy(t *testing.T) {
	engine := newListGetter("docker")
	f := NewFetcherEngine(context.Background(), make(chan string), nil, []DeferredContainers{{Engine: engine, RetryList: true}}).(*fetcher)
	assert.Empty(t, f.getters)
	require.Len(t, f.pendingEngines, 1)
	assert.Same(t, engine, f.pendingEngines[0].engine)
	assert.Empty(t, f.deferred)
	assert.Empty(t, f.namespaces)
}
