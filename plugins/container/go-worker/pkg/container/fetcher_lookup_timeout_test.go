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
// done, like a runtime socket that hangs after startup.
type hangingGetter struct {
	mu      sync.Mutex
	lookups int
}

func (g *hangingGetter) get(ctx context.Context, _ string) (*event.Event, error) {
	g.mu.Lock()
	g.lookups++
	g.mu.Unlock()
	<-ctx.Done()
	return nil, ctx.Err()
}

func (g *hangingGetter) count() int {
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
	hanging := &hangingGetter{}
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
// instead of stalling the single fetcher goroutine.
func TestFetcherDeferredLookupHonoursEngineTimeout(t *testing.T) {
	setEngineTimeout(t, 1)
	hanging := &hangingGetter{}
	healthy := newCountingGetter(1)
	fetchCh := make(chan string)
	f := newTestFetcherGetters([]getter{hanging, healthy}, fetchCh, fastBackoff, maxPendingFetches, []string{"aabbccddeeff"})
	outCh := runFetcher(t, f)

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
