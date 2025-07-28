package container

import (
	"context"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"sync"
	"time"
)

/*
Fetcher is a fake engine that listens on a channel for published containerIDs.
Everytime a containerID is published on the channel, the fetcher engine loops
over all enabled engines and tries to get info about the container,
until it succeeds and publish an event to the output channel.
FetcherChan requests are published through a CGO exposed API: AskForContainerInfo(), in worker_api.
*/

type fetcher struct {
	getters     []getter
	ctx         context.Context
	fetcherChan chan string
}

// NewFetcherEngine returns a fetcher engine.
// The fetcher engine is responsible to allow us to get() single container
// trying all container engines enabled.
func NewFetcherEngine(_ context.Context, fetcherChan chan string, containerEngines []Engine) Engine {
	f := fetcher{
		getters: make([]getter, len(containerEngines)),
		// Since podman relies upon context to store
		// connection-related info,
		// we need a unique context for fetcher
		// to avoid tampering with real podman engine context.
		ctx:         context.Background(),
		fetcherChan: fetcherChan,
	}
	for i, engine := range containerEngines {
		copyEngine, ok := engine.(copier)
		if !ok {
			// We need all engines to implement the copier interface to be copied by fetcher.
			panic("not a copier")
		}
		e, _ := copyEngine.copy(f.ctx)
		if e != nil {
			// No type check since Engine interface extends getter.
			f.getters[i] = e.(getter)
		}
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
// In case the container info is missing, due to a timing issue of the unterlying engines
// a retry is set up every containerFetchRetryInterval until containerFetchRetryTimeout is reached.
// On success, publish event on output channel.
func (f *fetcher) Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error) {
	const containerFetchRetryInterval = 10 * time.Millisecond
	const containerFetchRetryTimeout = time.Second
	outCh := make(chan event.Event)
	wg.Add(1)
	go func() {
		defer func() {
			close(outCh)
			wg.Done()
		}()
		containerFirstSeen := make(map[string]time.Time)
		for {
			select {
			case <-ctx.Done():
				return
			case containerId := <-f.fetcherChan:
				found := false
				now := time.Now()
				if containerRequestTime, exists := containerFirstSeen[containerId]; exists {
					if now.Sub(containerRequestTime) > containerFetchRetryTimeout {
						delete(containerFirstSeen, containerId)
						break
					}
				} else {
					containerFirstSeen[containerId] = now
				}
				for _, e := range f.getters {
					evt, _ := e.get(f.ctx, containerId)
					if evt != nil {
						outCh <- *evt
						found = true
						delete(containerFirstSeen, containerId)
						break
					}
				}
				if !found {
					go func() {
						time.Sleep(containerFetchRetryInterval)
						f.fetcherChan <- containerId
					}()
				}
			}
		}
	}()
	return outCh, nil
}
