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

// ready is a closed channel: receiving from it never blocks. It stands for
// the deferred containers in the select of serve, while there are some.
var ready = func() chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}()

type fetcher struct {
	getters     []getter
	ctx         context.Context
	fetcherChan chan string
	// Delays between the lookups of a container the engines do not know yet.
	retryBackoff []time.Duration
	// Bound on the containers waiting for a retry.
	maxPending int
	// The containers the startup listing enumerated but did not inspect
	// within the engine timeout, waiting for their lookup in the order given,
	// and their runtime identities. A successful request removes the identity
	// so its deferred slot is skipped. A miss retains it through retries.
	// Both are only touched by the serving goroutine.
	deferred        []string
	deferredLookups map[string]deferredFetch
}

// deferredFetch keeps runtime identity until lookup succeeds or retries end.
// Process requests use the same short-ID key, so they share this lookup too.
type deferredFetch struct {
	engine getter
	ref    ContainerRef
	queued bool // its background slot has not been consumed yet
}

func (d deferredFetch) get(ctx context.Context) (*event.Event, error) {
	if c, ok := d.engine.(*containerdEngine); ok {
		return c.getInNamespace(ctx, d.ref.Namespace, d.ref.ID)
	}
	return d.engine.get(ctx, d.ref.ID)
}

// NewFetcherEngine returns a fetcher engine.
// The fetcher engine is responsible to allow us to get() single container
// trying all container engines enabled. Once listening, it also looks up the
// deferred containers, the ones the startup listing enumerated but did not
// inspect in time (see ListIncompleteError), in the background.
func NewFetcherEngine(_ context.Context, fetcherChan chan string, containerEngines []Engine, deferred []DeferredContainers) Engine {
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
	// Only construction needs the engine index. The serving goroutine uses
	// direct getter references, including for normal short-ID requests.
	var copied map[[2]string]getter
	if len(deferred) > 0 {
		copied = make(map[[2]string]getter, len(containerEngines))
		count := 0
		for _, group := range deferred {
			count += len(group.Containers)
		}
		f.deferred = make([]string, 0, count)
		f.deferredLookups = make(map[string]deferredFetch, count)
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
		g := e.(getter)
		f.getters = append(f.getters, g)
		if copied != nil {
			copied[[2]string{engine.Name(), engine.Sock()}] = g
		}
	}
	for _, group := range deferred {
		g := copied[[2]string{group.Engine.Name(), group.Engine.Sock()}]
		if g == nil {
			// The failed engine copy was logged above.
			continue
		}
		for _, ref := range group.Containers {
			id := shortContainerID(ref.ID)
			if _, dup := f.deferredLookups[id]; id == "" || dup {
				continue
			}
			f.deferredLookups[id] = deferredFetch{engine: g, ref: ref, queued: true}
			f.deferred = append(f.deferred, id)
		}
	}
	if len(f.deferred) == 0 {
		f.deferred, f.deferredLookups = nil, nil
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
// A single goroutine and a single timer serve the requests, the retries and
// the deferred containers of the startup listing. Requests and due retries
// share the foreground; one deferred lookup runs when neither is ready.
// At most maxPending containers wait for a retry and each deferred container
// is looked up once: neither goroutines nor memory grow
// with the misses.
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
	if len(f.deferred) > 0 {
		slog.Default().LogAttrs(ctx, slog.LevelDebug, "looking up the containers the startup listing did not inspect in time",
			slog.Int("containers", len(f.deferred)))
	}
	for {
		if len(f.deferred) == 0 {
			select {
			case <-ctx.Done():
				return
			case containerId, ok := <-f.fetcherChan:
				if !ok {
					return
				}
				f.serveRequest(ctx, containerId, retries, outCh)
			case now := <-timerC:
				f.serveRetry(ctx, now, retries, outCh)
			}
		} else {
			// Live requests and their due retries both precede background
			// startup work. A busy request channel must not starve retries.
			select {
			case <-ctx.Done():
				return
			case containerId, ok := <-f.fetcherChan:
				if !ok {
					return
				}
				f.serveRequest(ctx, containerId, retries, outCh)
			case now := <-timerC:
				f.serveRetry(ctx, now, retries, outCh)
			default:
				select {
				case <-ctx.Done():
					return
				case containerId, ok := <-f.fetcherChan:
					if !ok {
						return
					}
					f.serveRequest(ctx, containerId, retries, outCh)
				case now := <-timerC:
					f.serveRetry(ctx, now, retries, outCh)
				case <-ready:
					f.serveDeferred(ctx, retries, outCh)
				}
			}
		}
		if len(f.deferred) == 0 && len(f.deferredLookups) == 0 {
			f.deferredLookups = nil
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

// serveRequest looks up a container the plugin asked for, unless it already
// waits for a retry, and schedules the retries of a miss.
func (f *fetcher) serveRequest(ctx context.Context, containerId string, retries *retryQueue, outCh chan<- event.Event) {
	if retries.contains(containerId) || f.lookup(ctx, containerId, outCh) {
		return
	}
	f.scheduleRetry(ctx, containerId, retries)
}

// scheduleRetry queues the first retry of a container that just missed, within
// the bound on the pending retries.
func (f *fetcher) scheduleRetry(ctx context.Context, containerId string, retries *retryQueue) {
	if retries.len() >= f.maxPending {
		slog.Default().LogAttrs(ctx, slog.LevelDebug, "too many containers waiting for a retry, dropping the request",
			slog.String("container", containerId), slog.Int("pending", retries.len()))
		f.forgetFailedDeferred(containerId)
		return
	}
	now := time.Now()
	if !retries.add(pendingFetch{id: containerId, since: now}, 0, now) {
		f.forgetFailedDeferred(containerId)
	}
}

// serveRetry looks up the earliest retry due at now, if any, and schedules
// the next retry of a miss, or gives the container up past the backoff.
func (f *fetcher) serveRetry(ctx context.Context, now time.Time, retries *retryQueue, outCh chan<- event.Event) {
	p, step, ok := retries.peek()
	if !ok || p.due.After(now) {
		// Stale tick
		return
	}
	retries.pop(step)
	if f.lookup(ctx, p.id, outCh) {
		retries.remove(p.id)
		return
	}
	// Pace the next lookup from the end of this one, as for a first miss, so
	// that a runtime slow to answer gets the whole delay.
	now = time.Now()
	if !retries.add(p, step+1, now) {
		f.forgetFailedDeferred(p.id)
		slog.Default().LogAttrs(ctx, slog.LevelDebug, "no container engine knows the container, giving up",
			slog.String("container", p.id), slog.Int("lookups", step+2), slog.Duration("elapsed", now.Sub(p.since)))
	}
}

// serveDeferred looks up the next deferred container, unless a request took
// care of it meanwhile. A miss is retried like a request's: the runtime
// enumerated the container at startup, so it usually knows it, but it may be
// gone by now.
func (f *fetcher) serveDeferred(ctx context.Context, retries *retryQueue, outCh chan<- event.Event) {
	id := f.deferred[0]
	f.deferred[0] = "" // do not retain the id
	f.deferred = f.deferred[1:]
	d, waiting := f.deferredLookups[id]
	if waiting {
		d.queued = false
		f.deferredLookups[id] = d
	}
	if len(f.deferred) == 0 {
		f.deferred = nil
		slog.Default().LogAttrs(ctx, slog.LevelDebug, "looked up every container the startup listing did not inspect in time")
	}
	if !waiting || retries.contains(id) || f.lookup(ctx, id, outCh) {
		return
	}
	f.scheduleRetry(ctx, id, retries)
}

// A failed process request must not discard the background attempt still
// waiting in the startup slice. Once that slot runs, only retries retain it.
func (f *fetcher) forgetFailedDeferred(id string) {
	if !f.deferredLookups[id].queued {
		delete(f.deferredLookups, id)
	}
}

// lookup uses the known runtime identity of a deferred container, or probes
// the engines for an unknown ID. Success publishes the event and releases
// any deferred identity.
func (f *fetcher) lookup(ctx context.Context, containerId string, outCh chan<- event.Event) bool {
	var evt *event.Event
	if d, ok := f.deferredLookups[containerId]; ok {
		evt, _ = d.get(f.ctx)
	} else {
		for _, e := range f.getters {
			evt, _ = e.get(f.ctx, containerId)
			if evt != nil {
				break
			}
		}
	}
	if evt != nil {
		delete(f.deferredLookups, containerId)
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
