package container

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

// hangingGetter accepts a lookup and never answers it until its context is
// done, like a runtime socket that hangs after startup. Every entry is
// signalled on a per-ID channel, so tests can wait for a specific lookup to
// reach the engine instead of inferring progress from a call count.
type hangingGetter struct {
	mu      sync.Mutex
	lookups int
	signals map[string]chan struct{}
}

func newHangingGetter() *hangingGetter {
	return &hangingGetter{signals: make(map[string]chan struct{})}
}

func (g *hangingGetter) get(ctx context.Context, containerId string) (*event.Event, error) {
	g.mu.Lock()
	g.lookups++
	signal, ok := g.signals[containerId]
	if !ok {
		signal = make(chan struct{}, 1)
		g.signals[containerId] = signal
	}
	g.mu.Unlock()
	select {
	case signal <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func (g *hangingGetter) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lookups
}

// entered returns a channel that receives once per lookup of containerId.
// The entry is created on first use by either side, so the channel is
// stable however the lookup and the test interleave.
func (g *hangingGetter) entered(containerId string) <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	signal, ok := g.signals[containerId]
	if !ok {
		signal = make(chan struct{}, 1)
		g.signals[containerId] = signal
	}
	return signal
}

// slowEnrichmentGetter answers its first lookup only once its context has
// expired, and still returns an event with partial metadata, like Docker's
// getter when ImageInspect times out mid-enrichment. Later lookups answer
// with the full identity.
type slowEnrichmentGetter struct {
	mu      sync.Mutex
	lookups int
}

func (g *slowEnrichmentGetter) get(ctx context.Context, containerId string) (*event.Event, error) {
	g.mu.Lock()
	g.lookups++
	calls := g.lookups
	g.mu.Unlock()
	if calls == 1 {
		<-ctx.Done()
		// The engine answered past the deadline: an event whose
		// enrichment was interrupted is not complete metadata.
		return &event.Event{Info: event.Info{Container: event.Container{ID: containerId}}, IsCreate: true}, nil
	}
	return &event.Event{
		Info: event.Info{Container: event.Container{
			ID:          containerId,
			FullID:      containerId,
			Image:       "registry.example/" + containerId + ":latest",
			ImageDigest: "sha256:0123456789abcdef",
		}},
		IsCreate: true,
	}, nil
}

func (g *slowEnrichmentGetter) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.lookups
}

// newTestFetcherGetters is newTestFetcher with an explicit getter list.
func newTestFetcherGetters(getters []getter, fetchCh chan string, backoff []time.Duration, maxPending int, deferred []string) *fetcher {
	f := &fetcher{
		getters:         getters,
		ctx:             context.Background(),
		fetcherChan:     fetchCh,
		retryBackoff:    backoff,
		maxPending:      maxPending,
		deferred:        append([]string(nil), deferred...),
		deferredLookups: make(map[string]deferredFetch, len(deferred)),
	}
	for _, id := range deferred {
		f.deferredLookups[id] = deferredFetch{engine: getters[0], ref: ContainerRef{ID: id}, queued: true}
	}
	return f
}

// TestFetcherRequestLookupHonoursEngineTimeout feeds the fetcher a request
// that a hanging engine never answers: the lookup must give way once the
// engine timeout expires and consult the next engine with a fresh bound,
// instead of blocking the fetcher goroutine for good.
func TestFetcherRequestLookupHonoursEngineTimeout(t *testing.T) {
	setEngineTimeout(t, 1)
	hanging := newHangingGetter()
	healthy := newCountingGetter(1)
	fetchCh := make(chan string)
	f := newTestFetcherGetters([]getter{hanging, healthy}, fetchCh, fastBackoff, maxPendingFetches, nil)
	outCh := runFetcher(t, f)

	start := time.Now()
	fetchCh <- "late"
	evt := waitOnChannelOrTimeout(t, outCh)
	assert.Equal(t, "late", evt.ID)
	// The hanging engine burned its whole engine timeout before the healthy
	// one answered, but no more.
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, time.Second)
	assert.Less(t, elapsed, 5*time.Second)
}

// TestFetcherDeferredLookupHonoursEngineTimeout defers a startup container
// to a hanging engine, then asks for a live container: the deferred lookup
// must return once the engine timeout expires so the request can be served,
// instead of stalling the single fetcher goroutine. Waiting for the deferred
// lookup to enter the engine makes the ordering explicit: the live request
// cannot overtake the background lookup still hanging inside the getter.
func TestFetcherDeferredLookupHonoursEngineTimeout(t *testing.T) {
	setEngineTimeout(t, 1)
	hanging := newHangingGetter()
	healthy := newCountingGetter(1)
	fetchCh := make(chan string)
	f := newTestFetcherGetters([]getter{hanging, healthy}, fetchCh, fastBackoff, maxPendingFetches, []string{"aabbccddeeff"})
	outCh := runFetcher(t, f)

	// The deferred startup lookup reaches the hanging engine before the
	// live request is even sent.
	select {
	case <-hanging.entered("aabbccddeeff"):
	case <-time.After(5 * time.Second):
		t.Error("timed out waiting for the deferred lookup to enter the engine")
	}

	start := time.Now()
	fetchCh <- "late"
	evt := waitOnChannelOrTimeout(t, outCh)
	assert.Equal(t, "late", evt.ID)
	elapsed := time.Since(start)
	assert.GreaterOrEqual(t, elapsed, time.Second)
	assert.Less(t, elapsed, 5*time.Second)
	// The deferred startup lookup and the live request both consulted the
	// hanging engine, each within the engine timeout.
	assert.Eventually(t, func() bool { return hanging.count() >= 2 }, 5*time.Second, 10*time.Millisecond)
}

// TestFetcherRequestLookupExpiredIsRetried serves a request whose first
// lookup expires during metadata enrichment: the engine answers past the
// deadline with an event whose enrichment was interrupted, and that partial
// metadata must not be published. The fetcher retries, and the full identity
// of the live request is served.
func TestFetcherRequestLookupExpiredIsRetried(t *testing.T) {
	setEngineTimeout(t, 1)
	slow := &slowEnrichmentGetter{}
	fetchCh := make(chan string)
	f := newTestFetcherGetters([]getter{slow}, fetchCh, fastBackoff, maxPendingFetches, nil)
	outCh := runFetcher(t, f)

	fetchCh <- "late"
	evt := waitOnChannelOrTimeout(t, outCh)
	// The expired attempt's partial event was dropped: the first published
	// event carries the full identity of the retry.
	assert.Equal(t, "late", evt.ID)
	assert.Equal(t, "late", evt.FullID)
	assert.Equal(t, "registry.example/late:latest", evt.Image)
	assert.Equal(t, "sha256:0123456789abcdef", evt.ImageDigest)
	// One expired attempt, one successful retry.
	assert.Equal(t, 2, slow.count())
}

// TestFetcherDeferredLookupExpiredKeepsIdentityAndRetries defers a startup
// container whose lookup expires during metadata enrichment: the engine
// answers past the deadline with an event whose enrichment was interrupted,
// and that partial metadata must not be published. The deferred identity is
// preserved, so the retry completes it instead of the C++ cache considering
// the container resolved.
func TestFetcherDeferredLookupExpiredKeepsIdentityAndRetries(t *testing.T) {
	setEngineTimeout(t, 1)
	slow := &slowEnrichmentGetter{}
	fetchCh := make(chan string)
	f := newTestFetcherGetters([]getter{slow}, fetchCh, fastBackoff, maxPendingFetches, []string{"aabbccddeeff"})
	outCh := runFetcher(t, f)

	// If the expired attempt's partial event were published, the first
	// event would leak an empty image and digest: the assertions below
	// fail on it. With it dropped, the first event is the complete retry.
	evt := waitOnChannelOrTimeout(t, outCh)
	assert.Equal(t, "aabbccddeeff", evt.ID)
	assert.Equal(t, "aabbccddeeff", evt.FullID)
	assert.Equal(t, "registry.example/aabbccddeeff:latest", evt.Image)
	assert.Equal(t, "sha256:0123456789abcdef", evt.ImageDigest)
	// One expired attempt, one successful retry.
	assert.Equal(t, 2, slow.count())
}
