package container

import (
	"context"
	"fmt"
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
