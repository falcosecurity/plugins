package container

import (
	"context"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"sync"
)

/*
Fetcher is a fake engine that listens on fetcherChan for published containerIDs.
Everytime a containerID is published on the channel, the fetcher engine loops
over all enabled engines and tries to get info about the container,
until it succeeds and publish an event to the output channel.
FetcherChan requests are published through a CGO exposed API: AskForContainerInfo(), in worker_api.
*/

var fetcherChan chan string

func GetFetcherChan() chan<- string {
	return fetcherChan
}

type fetcher struct {
	getters []getter
}

// NewFetcherEngine returns a fetcher engine.
// The fetcher engine is responsible to allow us to get() single container
// trying all container engines enabled.
func NewFetcherEngine(ctx context.Context, containerEngines []Engine) Engine {
	f := fetcher{
		getters: make([]getter, len(containerEngines)),
	}
	for i, engine := range containerEngines {
		copyEngine, ok := engine.(copier)
		if !ok {
			// We need all engines to implement the copier interface to be copied by fetcher.
			panic("not a copier")
		}
		e, _ := copyEngine.copy(ctx)
		if e != nil {
			// No type check since Engine interface extends getter.
			f.getters[i] = e.(getter)
		}
	}
	return &f
}

func (f *fetcher) List(_ context.Context) ([]event.Event, error) {
	panic("do not call")
}

func (f *fetcher) Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error) {
	outCh := make(chan event.Event)
	wg.Add(1)
	fetcherChan = make(chan string)
	go func() {
		defer func() {
			close(outCh)
			close(fetcherChan)
			fetcherChan = nil
			wg.Done()
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case containerId := <-fetcherChan:
				for _, e := range f.getters {
					evt, _ := e.get(ctx, containerId)
					if evt != nil {
						outCh <- *evt
						break
					}
				}
			}
		}
	}()
	return outCh, nil
}
