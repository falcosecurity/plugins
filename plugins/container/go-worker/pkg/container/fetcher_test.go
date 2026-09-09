package container

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

func TestDockerFetcher(t *testing.T) {
	testDocker(t, true)
}

func TestContainerdFetcher(t *testing.T) {
	testContainerd(t, true)
}

func TestPodmanFetcher(t *testing.T) {
	testPodman(t, true)
}

func TestCRIFakeFetcher(t *testing.T) {
	testCRIFake(t, true)
}

func TestCRIFetcher(t *testing.T) {
	testCRI(t, true)
}

func testFetcher(t *testing.T, containerEngine Engine, containerId string, expectedEvent event.Event) {
	// Create the fetcher engine with the docker engine as the only container engine
	containerEngines := []Engine{containerEngine}
	fetchCh := make(chan string)
	assert.NotNil(t, fetchCh)
	t.Cleanup(func() {
		close(fetchCh)
	})

	f := NewFetcherEngine(context.Background(), fetchCh, containerEngines)
	assert.NotNil(t, f)

	// Check that fetcher is able to fetch the container
	wg := sync.WaitGroup{}
	cancelCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	listCh, err := f.Listen(cancelCtx, &wg)
	assert.NoError(t, err)

	// Send the container ID to the fetcher channel to request its info to be loaded
	go func() {
		time.Sleep(1 * time.Second)
		fetchCh <- containerId
	}()

	evt := waitOnChannelOrTimeout(t, listCh)
	// This needs to be updated on the fly
	expectedEvent.CreatedTime = evt.CreatedTime
	// In some cases, the env ordering might differ thus we manually check it and then copy it
	for _, env := range expectedEvent.Env {
		assert.Contains(t, evt.Env, env)
	}
	expectedEvent.Env = evt.Env
	assert.Equal(t, expectedEvent, evt)
}

// countingGetter records every lookup and answers a container from its
// answerAt-th lookup on; it never answers when answerAt is zero.
type countingGetter struct {
	mu       sync.Mutex
	answerAt int
	lookups  map[string][]time.Time
}

func newCountingGetter(answerAt int) *countingGetter {
	return &countingGetter{answerAt: answerAt, lookups: make(map[string][]time.Time)}
}

func (g *countingGetter) get(_ context.Context, containerId string) (*event.Event, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lookups[containerId] = append(g.lookups[containerId], time.Now())
	if g.answerAt > 0 && len(g.lookups[containerId]) >= g.answerAt {
		return &event.Event{Info: event.Info{Container: event.Container{ID: containerId}}, IsCreate: true}, nil
	}
	return nil, errors.New("no such container")
}

// count returns the lookups done for the container.
func (g *countingGetter) count(containerId string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.lookups[containerId])
}

// snapshot returns a copy of the lookups done so far.
func (g *countingGetter) snapshot() map[string][]time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	lookups := make(map[string][]time.Time, len(g.lookups))
	for id, l := range g.lookups {
		lookups[id] = append([]time.Time(nil), l...)
	}
	return lookups
}

// startFetcher serves the fetch requests through g, with the given retry
// backoff and pending bound, until the test ends. It then checks that the
// fetcher left no goroutine behind.
func startFetcher(t *testing.T, g getter, backoff []time.Duration, maxPending int) (chan<- string, <-chan event.Event) {
	t.Helper()
	fetchCh := make(chan string)
	f := &fetcher{
		getters:      []getter{g},
		ctx:          context.Background(),
		fetcherChan:  fetchCh,
		retryBackoff: backoff,
		maxPending:   maxPending,
	}
	goroutines := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	outCh, err := f.Listen(ctx, &wg)
	require.NoError(t, err)
	t.Cleanup(func() {
		cancel()
		wg.Wait()
		close(fetchCh)
		for deadline := time.Now().Add(time.Second); runtime.NumGoroutine() > goroutines && time.Now().Before(deadline); {
			time.Sleep(10 * time.Millisecond)
		}
		assert.LessOrEqual(t, runtime.NumGoroutine(), goroutines, "the fetcher leaked goroutines")
	})
	return fetchCh, outCh
}

func sumDurations(ds []time.Duration) time.Duration {
	var sum time.Duration
	for _, d := range ds {
		sum += d
	}
	return sum
}

// assertNoEvent fails if ch delivers an event within d.
func assertNoEvent(t *testing.T, ch <-chan event.Event, d time.Duration) {
	t.Helper()
	select {
	case evt := <-ch:
		t.Errorf("unexpected event for container %q", evt.ID)
	case <-time.After(d):
	}
}

var fastBackoff = []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond}

func TestFetcherRetriesUntilFound(t *testing.T) {
	g := newCountingGetter(3) // known from the second retry on
	fetchCh, outCh := startFetcher(t, g, fastBackoff, maxPendingFetches)

	start := time.Now()
	fetchCh <- "late"
	evt := waitOnChannelOrTimeout(t, outCh)
	assert.Equal(t, "late", evt.ID)
	assert.True(t, evt.IsCreate)
	assert.Equal(t, 3, g.count("late"))
	assert.GreaterOrEqual(t, time.Since(start), fastBackoff[0]+fastBackoff[1])

	// Once found, the container is neither looked up nor published again.
	assertNoEvent(t, outCh, sumDurations(fastBackoff))
	assert.Equal(t, 3, g.count("late"))
}

func TestFetcherGivesUpAfterTheBackoff(t *testing.T) {
	g := newCountingGetter(0) // never known
	fetchCh, outCh := startFetcher(t, g, fastBackoff, maxPendingFetches)

	fetchCh <- "unknown"
	assertNoEvent(t, outCh, 2*sumDurations(fastBackoff))
	// The first lookup, then one per step of the backoff, then nothing.
	assert.Equal(t, len(fastBackoff)+1, g.count("unknown"))

	// Asked again, e.g. once the plugin bookkeeping expired, it is looked up again.
	fetchCh <- "unknown"
	assert.Eventually(t, func() bool { return g.count("unknown") == len(fastBackoff)+2 }, time.Second, time.Millisecond)
}

func TestFetcherDeduplicatesPendingRequests(t *testing.T) {
	g := newCountingGetter(0)
	fetchCh, outCh := startFetcher(t, g, []time.Duration{100 * time.Millisecond}, maxPendingFetches)

	for i := 0; i < 3; i++ {
		fetchCh <- "dup"
	}
	// Only the first request is looked up: the others find a retry pending.
	assert.Equal(t, 1, g.count("dup"))
	assert.Eventually(t, func() bool { return g.count("dup") == 2 }, time.Second, time.Millisecond)
	assertNoEvent(t, outCh, 50*time.Millisecond)
	assert.Equal(t, 2, g.count("dup"))
}

// TestFetcherBoundedUnderManyMisses floods the fetcher with containers no
// engine knows. At most maxPending of them wait for a retry at any time, the
// others are dropped after their first lookup, every retried one goes through
// the whole backoff and no lookup is left running afterwards.
func TestFetcherBoundedUnderManyMisses(t *testing.T) {
	const (
		containers = 5000
		maxPending = 256
	)
	backoff := []time.Duration{5 * time.Millisecond, 10 * time.Millisecond, 20 * time.Millisecond, 40 * time.Millisecond, 80 * time.Millisecond}
	g := newCountingGetter(0)
	fetchCh, outCh := startFetcher(t, g, backoff, maxPending)

	start := time.Now()
	for i := 0; i < containers; i++ {
		fetchCh <- fmt.Sprintf("ctr%05d", i)
	}
	sent := time.Since(start)

	// The last container admitted for a retry is admitted while sending, so
	// by then every retry is over.
	assertNoEvent(t, outCh, sumDurations(backoff)+200*time.Millisecond)
	settled := time.Since(start)

	lookups := g.snapshot()
	require.Len(t, lookups, containers)
	retried, dropped, total := 0, 0, 0
	type edge struct {
		at    time.Time
		delta int
	}
	var edges []edge
	for id, l := range lookups {
		total += len(l)
		switch len(l) {
		case 1:
			dropped++
		case len(backoff) + 1:
			retried++
			// A retried container holds a slot from its first lookup, right
			// before it is admitted, to its last one, right before it is
			// given up.
			edges = append(edges, edge{l[0], +1}, edge{l[len(l)-1], -1})
		default:
			t.Errorf("container %s: %d lookups, want 1 or %d", id, len(l), len(backoff)+1)
		}
	}
	assert.Equal(t, containers, retried+dropped)
	assert.GreaterOrEqual(t, retried, maxPending)
	assert.Equal(t, dropped+retried*(len(backoff)+1), total)

	// At no time more than maxPending containers were waiting for a retry.
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].at.Equal(edges[j].at) {
			return edges[i].delta < edges[j].delta
		}
		return edges[i].at.Before(edges[j].at)
	})
	pending, maxInFlight := 0, 0
	for _, e := range edges {
		pending += e.delta
		maxInFlight = max(maxInFlight, pending)
	}
	assert.Equal(t, maxPending, maxInFlight)

	// Nothing is left running.
	assertNoEvent(t, outCh, 2*backoff[len(backoff)-1])
	assert.Len(t, g.snapshot(), containers)
	after := 0
	for _, l := range g.snapshot() {
		after += len(l)
	}
	assert.Equal(t, total, after)

	t.Logf("%d containers sent in %v (%.0f req/s), settled after %v: %d retried, %d dropped, %d lookups, %d max pending",
		containers, sent, float64(containers)/sent.Seconds(), settled, retried, dropped, total, maxInFlight)
}

// slowGetter never knows a container and takes delay to say so, like a
// runtime under load. It records when each lookup started.
type slowGetter struct {
	mu     sync.Mutex
	delay  time.Duration
	starts []time.Time
}

func (g *slowGetter) get(context.Context, string) (*event.Event, error) {
	g.mu.Lock()
	g.starts = append(g.starts, time.Now())
	g.mu.Unlock()
	time.Sleep(g.delay)
	return nil, errors.New("no such container")
}

// lookups returns a copy of the lookup start times.
func (g *slowGetter) lookups() []time.Time {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]time.Time(nil), g.starts...)
}

// TestFetcherPacesRetriesFromTheEndOfTheLookup checks that the time a lookup
// takes does not eat into the delay before the next one: a runtime slow to
// answer gets the whole backoff of rest between two lookups.
func TestFetcherPacesRetriesFromTheEndOfTheLookup(t *testing.T) {
	backoff := []time.Duration{20 * time.Millisecond, 40 * time.Millisecond}
	g := &slowGetter{delay: 30 * time.Millisecond}
	fetchCh, outCh := startFetcher(t, g, backoff, maxPendingFetches)

	fetchCh <- "slow"
	assert.Eventually(t, func() bool { return len(g.lookups()) == len(backoff)+1 }, time.Second, time.Millisecond)
	assertNoEvent(t, outCh, 50*time.Millisecond)

	starts := g.lookups()
	require.Len(t, starts, len(backoff)+1)
	for i, delay := range backoff {
		assert.GreaterOrEqual(t, starts[i+1].Sub(starts[i]), g.delay+delay, "lookup %d started less than its delay after the end of lookup %d", i+1, i)
	}
}

type nopGetter struct{}

func (nopGetter) get(context.Context, string) (*event.Event, error) {
	return nil, nil
}

// BenchmarkFetcherMiss measures a request for a container no engine knows,
// with the default backoff and bound, the retries running in the background.
func BenchmarkFetcherMiss(b *testing.B) {
	fetchCh := make(chan string)
	f := &fetcher{
		getters:      []getter{nopGetter{}},
		ctx:          context.Background(),
		fetcherChan:  fetchCh,
		retryBackoff: containerFetchRetryBackoff,
		maxPending:   maxPendingFetches,
	}
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	if _, err := f.Listen(ctx, &wg); err != nil {
		b.Fatal(err)
	}
	ids := make([]string, 1<<14)
	for i := range ids {
		ids[i] = fmt.Sprintf("ctr%05d", i)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fetchCh <- ids[i%len(ids)]
	}
	b.StopTimer()
	cancel()
	wg.Wait()
}

// BenchmarkRetryQueue measures the bookkeeping of one retry while the bound
// of containers is pending.
func BenchmarkRetryQueue(b *testing.B) {
	q := newRetryQueue(containerFetchRetryBackoff)
	now := time.Now()
	for i := 0; i < maxPendingFetches; i++ {
		q.add(pendingFetch{id: fmt.Sprintf("ctr%05d", i), since: now}, 0, now)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p, step, _ := q.peek()
		q.pop(step)
		if !q.add(p, step+1, now) {
			q.add(p, 0, now)
		}
	}
}
