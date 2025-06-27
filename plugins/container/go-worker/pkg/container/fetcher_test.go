package container

import (
	"context"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"time"
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
