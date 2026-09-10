package container

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

type lookupFunc func(context.Context, string) (*event.Event, error)

func (f lookupFunc) get(ctx context.Context, id string) (*event.Event, error) {
	return f(ctx, id)
}

type namespaceLookup struct {
	lookupFunc
	list func(context.Context, string) ([]ContainerRef, error)
}

func (e namespaceLookup) listNamespace(ctx context.Context, namespace string) ([]ContainerRef, error) {
	return e.list(ctx, namespace)
}

func TestFetcherRetriesNamespacesWithoutDroppingOtherWork(t *testing.T) {
	var recovered atomic.Bool
	g := namespaceLookup{
		lookupFunc: func(_ context.Context, id string) (*event.Event, error) {
			return &event.Event{Info: event.Info{Container: event.Container{ID: id}}}, nil
		},
		list: func(_ context.Context, namespace string) ([]ContainerRef, error) {
			if namespace == "slow" && !recovered.Load() {
				return nil, errors.New("temporarily unavailable")
			}
			if namespace == "empty" {
				return nil, nil
			}
			return []ContainerRef{{ID: namespace}}, nil
		},
	}
	// A namespace job must survive even with no container retry slots. Empty
	// namespaces finish normally, and a failing namespace cannot stall others.
	f := newTestFetcher(g, make(chan string), fastBackoff, 0, nil)
	for _, ns := range []string{"slow", "empty", "healthy"} {
		f.namespaces = append(f.namespaces, &deferredNamespace{engine: g, name: ns})
	}
	out := runFetcher(t, f)
	assert.Equal(t, "healthy", waitOnChannelOrTimeout(t, out).ID)
	recovered.Store(true)
	assert.Equal(t, "slow", waitOnChannelOrTimeout(t, out).ID)
	assertNoEvent(t, out, 2*sumDurations(fastBackoff))
}

func TestFetcherSlowNamespaceRetriesDoNotStarveLaterNamespaces(t *testing.T) {
	g := namespaceLookup{
		lookupFunc: func(_ context.Context, id string) (*event.Event, error) {
			return &event.Event{Info: event.Info{Container: event.Container{ID: id}}}, nil
		},
		list: func(ctx context.Context, namespace string) ([]ContainerRef, error) {
			if namespace == "healthy" {
				return []ContainerRef{{ID: namespace}}, nil
			}
			// Each failure takes longer than the maximum retry delay. If
			// retries run ahead of the background queue, these two jobs keep
			// one another due and the healthy namespace never gets a turn.
			timer := time.NewTimer(15 * time.Millisecond)
			defer timer.Stop()
			select {
			case <-timer.C:
				return nil, errors.New("slow failure")
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		},
	}
	f := newTestFetcher(g, make(chan string), []time.Duration{time.Millisecond, 2 * time.Millisecond}, maxPendingFetches, nil)
	for _, ns := range []string{"slow-one", "slow-two", "healthy"} {
		f.namespaces = append(f.namespaces, &deferredNamespace{engine: g, name: ns})
	}
	assert.Equal(t, "healthy", waitOnChannelOrTimeout(t, runFetcher(t, f)).ID)
}

func TestFetcherCancelsNamespaceEnumeration(t *testing.T) {
	for _, timeout := range []int{0, 1} {
		t.Run(fmt.Sprintf("timeout=%d", timeout), func(t *testing.T) {
			setEngineTimeout(t, timeout)
			entered := make(chan context.Context, 1)
			g := namespaceLookup{list: func(ctx context.Context, _ string) ([]ContainerRef, error) {
				entered <- ctx
				<-ctx.Done()
				return nil, ctx.Err()
			}}
			f := newTestFetcher(g, make(chan string), fastBackoff, maxPendingFetches, nil)
			f.namespaces = []*deferredNamespace{{engine: g, name: "stalled"}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() {
				defer close(done)
				f.serve(ctx, make(chan event.Event))
			}()
			select {
			case requestCtx := <-entered:
				_, bounded := requestCtx.Deadline()
				assert.Equal(t, timeout > 0, bounded)
			case <-time.After(time.Second):
				t.Fatal("namespace enumeration did not start")
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("namespace enumeration ignored shutdown")
			}
		})
	}
}

func TestFetcherBoundsNamespaceEnumeration(t *testing.T) {
	setEngineTimeout(t, 1)
	calls := 0
	g := namespaceLookup{list: func(ctx context.Context, _ string) ([]ContainerRef, error) {
		calls++
		if calls == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return []ContainerRef{{ID: "recovered"}}, nil
	}, lookupFunc: func(context.Context, string) (*event.Event, error) {
		return &event.Event{Info: event.Info{Container: event.Container{ID: "recovered"}}}, nil
	}}
	f := newTestFetcher(g, make(chan string), fastBackoff, maxPendingFetches, nil)
	f.namespaces = []*deferredNamespace{{engine: g, name: "stalled"}}
	start := time.Now()
	out := runFetcher(t, f)
	assert.Equal(t, "recovered", waitOnChannelOrTimeout(t, out).ID)
	assert.GreaterOrEqual(t, time.Since(start), time.Second)
}

func TestFetcherRetriesWhileRequestsAndDeferredWorkWait(t *testing.T) {
	// A full channel models the initial thread scan. The first container
	// misses once; newer requests must not prevent its due retry.
	fetchCh := make(chan string, 100)
	fetchCh <- "target"
	for i := 0; i < 99; i++ {
		fetchCh <- fmt.Sprintf("live-%03d", i)
	}
	lookups := 0
	g := lookupFunc(func(_ context.Context, id string) (*event.Event, error) {
		time.Sleep(time.Millisecond)
		if id == "target" {
			lookups++
			if lookups == 1 {
				return nil, nil
			}
		}
		return &event.Event{Info: event.Info{Container: event.Container{ID: id}}, IsCreate: true}, nil
	})
	f := newTestFetcher(g, fetchCh, []time.Duration{time.Millisecond}, maxPendingFetches, []string{"quiet"})
	out := runFetcher(t, f)
	before := 0
	for waitOnChannelOrTimeout(t, out).ID != "target" {
		before++
	}
	assert.Less(t, before, 99, "the retry waited for the entire request channel to drain")
}

func TestFetcherRetainsDeferredIdentityThroughRetry(t *testing.T) {
	for _, requested := range []bool{false, true} {
		t.Run(fmt.Sprintf("requested=%t", requested), func(t *testing.T) {
			fullID := "0123456789abcdef0123456789abcdef"
			id := shortContainerID(fullID)
			calls := 0
			origin := lookupFunc(func(_ context.Context, got string) (*event.Event, error) {
				assert.Equal(t, fullID, got)
				calls++
				if calls == 1 {
					return nil, nil
				}
				return &event.Event{Info: event.Info{Container: event.Container{ID: id, FullID: got}}}, nil
			})
			unrelated := lookupFunc(func(context.Context, string) (*event.Event, error) {
				t.Error("a known startup container was sent to an unrelated runtime")
				return nil, nil
			})
			f := newTestFetcher(unrelated, make(chan string), fastBackoff, maxPendingFetches, []string{id})
			f.deferredLookups[id] = deferredFetch{engine: origin, ref: ContainerRef{ID: fullID}, queued: true}
			out := make(chan event.Event, 1)
			retries := newRetryQueue(f.retryBackoff)
			if requested {
				f.serveRequest(context.Background(), id, retries, out)
				f.serveRequest(context.Background(), id, retries, out)
			}
			f.serveDeferred(context.Background(), retries, out)
			require.Equal(t, 1, calls)
			require.Empty(t, f.deferred)
			require.Len(t, f.deferredLookups, 1, "the full ID must survive draining the startup slice")
			pending, _, ok := retries.peek()
			require.True(t, ok)
			f.serveRetry(context.Background(), pending.due, retries, out)
			assert.Equal(t, fullID, waitOnChannelOrTimeout(t, out).FullID)
			assert.Equal(t, 2, calls)
			assert.Empty(t, f.deferredLookups)
			assert.Zero(t, retries.len())
		})
	}
}

func TestFetcherReleasesFailedDeferredIdentity(t *testing.T) {
	for _, limit := range []int{0, 1} {
		t.Run(fmt.Sprintf("pending_limit=%d", limit), func(t *testing.T) {
			f := newTestFetcher(nopGetter{}, make(chan string), fastBackoff, limit, []string{"gone"})
			retries := newRetryQueue(f.retryBackoff)
			out := make(chan event.Event, 1)
			f.serveDeferred(context.Background(), retries, out)
			for retries.len() > 0 {
				pending, _, _ := retries.peek()
				f.serveRetry(context.Background(), pending.due, retries, out)
			}
			assert.Empty(t, f.deferredLookups)
			assert.Empty(t, out)
		})
	}
}

func TestFetcherKeepsQueuedRecoveryAfterFailedRequest(t *testing.T) {
	for _, limit := range []int{0, 1} {
		t.Run(fmt.Sprintf("pending_limit=%d", limit), func(t *testing.T) {
			found := false
			g := lookupFunc(func(_ context.Context, id string) (*event.Event, error) {
				if !found {
					return nil, nil
				}
				return &event.Event{Info: event.Info{Container: event.Container{ID: id}}}, nil
			})
			f := newTestFetcher(g, make(chan string), fastBackoff, limit, []string{"late"})
			retries := newRetryQueue(f.retryBackoff)
			out := make(chan event.Event, 1)
			// Either admission fails immediately or all retries fail before
			// background work gets a turn. The queued attempt must survive.
			f.serveRequest(context.Background(), "late", retries, out)
			for retries.len() > 0 {
				pending, _, _ := retries.peek()
				f.serveRetry(context.Background(), pending.due, retries, out)
			}
			require.Len(t, f.deferredLookups, 1)
			found = true
			f.serveDeferred(context.Background(), retries, out)
			assert.Equal(t, "late", waitOnChannelOrTimeout(t, out).ID)
			assert.Empty(t, f.deferredLookups)
		})
	}
}
