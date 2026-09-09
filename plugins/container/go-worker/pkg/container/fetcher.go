package container

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

/*
Fetcher is a fake engine that listens on a channel for published containerIDs.
Everytime a containerID is published on the channel, the fetcher engine loops
over all enabled engines and tries to get info about the container,
until it succeeds and publish an event to the output channel.
FetcherChan requests are published through a CGO exposed API: AskForContainerInfo(), in worker_api.
*/

// containerFetchRetryBackoff paces the lookups of a container the engines do
// not know yet: a container can show up through the runtime API a while after
// its first process does, in particular under load. A miss is looked up again
// after each of these delays, about 4s in total, then the request is dropped.
// The plugin asks again on a later process event, once its own bookkeeping of
// the asked containers expires (see src/asked_containers.h).
var containerFetchRetryBackoff = []time.Duration{
	125 * time.Millisecond,
	250 * time.Millisecond,
	500 * time.Millisecond,
	time.Second,
	2 * time.Second,
}

// maxPendingFetches bounds the containers waiting for a retry, so that a
// runtime which keeps missing cannot grow the fetcher state without bound. A
// miss beyond the bound is dropped; the plugin asks again later.
const maxPendingFetches = 1024

type fetcher struct {
	getters     []getter
	ctx         context.Context
	fetcherChan chan string
	// Delays between the lookups of a container the engines do not know yet.
	retryBackoff []time.Duration
	// Bound on the containers waiting for a retry.
	maxPending int
}

// NewFetcherEngine returns a fetcher engine.
// The fetcher engine is responsible to allow us to get() single container
// trying all container engines enabled.
func NewFetcherEngine(_ context.Context, fetcherChan chan string, containerEngines []Engine) Engine {
	f := fetcher{
		getters: make([]getter, 0, len(containerEngines)),
		// Since podman relies upon context to store
		// connection-related info,
		// we need a unique context for fetcher
		// to avoid tampering with real podman engine context.
		ctx:          context.Background(),
		fetcherChan:  fetcherChan,
		retryBackoff: containerFetchRetryBackoff,
		maxPending:   maxPendingFetches,
	}
	for _, engine := range containerEngines {
		copyEngine, ok := engine.(copier)
		if !ok {
			// We need all engines to implement the copier interface to be copied by fetcher.
			panic("not a copier")
		}
		e, err := copyEngine.copy(f.ctx)
		if e == nil {
			// Leave the engine out rather than storing a nil getter, which
			// would make Listen panic on the first lookup.
			slog.Default().LogAttrs(f.ctx, slog.LevelWarn, "cannot copy container engine for on-demand lookups, skipping it",
				slog.String("engine", engine.Name()), slog.String("socket", engine.Sock()), slog.Any("err", err))
			continue
		}
		// No type check since Engine interface extends getter.
		f.getters = append(f.getters, e.(getter))
	}
	return &f
}

func (f *fetcher) Name() string {
	return ""
}

func (f *fetcher) Sock() string {
	return ""
}

func (f *fetcher) List(_ context.Context) ([]event.Event, error) {
	panic("do not call")
}

// Everytime a containerID is published on the fetcher channel, the fetcher engine loops
// over all enabled engines and tries to get info about the container.
// In case the container info is missing, due to a timing issue of the underlying engines,
// the lookup is retried after each delay of the retry backoff, then given up.
// On success, publish event on output channel.
// A single goroutine and a single timer serve both the requests and the
// retries, one retry per wake-up so that the requests are never starved, and
// at most maxPending containers wait for a retry: neither goroutines nor
// memory grow with the misses.
func (f *fetcher) Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error) {
	outCh := make(chan event.Event)
	wg.Add(1)
	go func() {
		defer func() {
			close(outCh)
			wg.Done()
		}()
		f.serve(ctx, outCh)
	}()
	return outCh, nil
}

func (f *fetcher) serve(ctx context.Context, outCh chan<- event.Event) {
	retries := newRetryQueue(f.retryBackoff)
	// The timer paces the retries. It starts drained and unarmed: timerC is
	// nil, hence never ready, while nothing is pending.
	timer := time.NewTimer(0)
	<-timer.C
	defer timer.Stop()
	var timerC <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case containerId, ok := <-f.fetcherChan:
			if !ok {
				return
			}
			if retries.contains(containerId) || f.lookup(ctx, containerId, outCh) {
				break
			}
			if retries.len() >= f.maxPending {
				slog.Default().LogAttrs(ctx, slog.LevelDebug, "too many containers waiting for a retry, dropping the request",
					slog.String("container", containerId), slog.Int("pending", retries.len()))
				break
			}
			now := time.Now()
			retries.add(pendingFetch{id: containerId, since: now}, 0, now)
		case now := <-timerC:
			p, step, ok := retries.peek()
			if !ok || p.due.After(now) {
				// Stale tick
				break
			}
			retries.pop(step)
			if f.lookup(ctx, p.id, outCh) {
				retries.remove(p.id)
			} else if !retries.add(p, step+1, now) {
				slog.Default().LogAttrs(ctx, slog.LevelDebug, "no container engine knows the container, giving up",
					slog.String("container", p.id), slog.Int("lookups", step+2), slog.Duration("elapsed", now.Sub(p.since)))
			}
		}
		// Arm the timer on the earliest retry, if any.
		if p, _, ok := retries.peek(); ok {
			timer.Reset(time.Until(p.due))
			timerC = timer.C
		} else {
			timerC = nil
		}
	}
}

// lookup asks each engine about the container and publishes the first
// answer. It reports whether an engine knew the container.
func (f *fetcher) lookup(ctx context.Context, containerId string, outCh chan<- event.Event) bool {
	for _, e := range f.getters {
		evt, _ := e.get(f.ctx, containerId)
		if evt == nil {
			continue
		}
		select {
		case outCh <- *evt:
		case <-ctx.Done():
		}
		return true
	}
	return false
}

// pendingFetch is a container whose lookup missed and waits for a retry.
type pendingFetch struct {
	id    string
	since time.Time // first lookup
	due   time.Time // next lookup
}

// retryQueue holds the pending fetches, in one FIFO per step of the backoff.
// Time is monotonic and every container in a step waits the same delay, so
// each FIFO is sorted by due time and the earliest retry overall is the
// earliest of the heads. Every operation is O(1) in the number of pending
// fetches.
type retryQueue struct {
	backoff []time.Duration
	steps   [][]pendingFetch
	ids     map[string]struct{}
}

func newRetryQueue(backoff []time.Duration) *retryQueue {
	return &retryQueue{
		backoff: backoff,
		steps:   make([][]pendingFetch, len(backoff)),
		ids:     make(map[string]struct{}),
	}
}

// len returns the number of containers waiting for a retry.
func (q *retryQueue) len() int {
	return len(q.ids)
}

// contains reports whether the container waits for a retry.
func (q *retryQueue) contains(id string) bool {
	_, ok := q.ids[id]
	return ok
}

// add schedules the given step of the backoff for a container that missed at
// now. It reports false, and forgets the container, when the backoff has no
// such step: the container is given up.
func (q *retryQueue) add(p pendingFetch, step int, now time.Time) bool {
	if step >= len(q.steps) {
		delete(q.ids, p.id)
		return false
	}
	p.due = now.Add(q.backoff[step])
	q.steps[step] = append(q.steps[step], p)
	q.ids[p.id] = struct{}{}
	return true
}

// peek returns the earliest retry and its step, if any.
func (q *retryQueue) peek() (pendingFetch, int, bool) {
	var earliest pendingFetch
	step := -1
	for i, s := range q.steps {
		if len(s) > 0 && (step < 0 || s[0].due.Before(earliest.due)) {
			earliest, step = s[0], i
		}
	}
	return earliest, step, step >= 0
}

// pop drops the head of the step. The caller either adds the container to
// the next step or removes it.
func (q *retryQueue) pop(step int) {
	q.steps[step][0] = pendingFetch{} // do not retain the id
	q.steps[step] = q.steps[step][1:]
}

// remove forgets a container that was found.
func (q *retryQueue) remove(id string) {
	delete(q.ids, id)
}
