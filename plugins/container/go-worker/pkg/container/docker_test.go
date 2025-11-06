package container

import (
	"context"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"testing"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"github.com/stretchr/testify/assert"
)

func testDocker(t *testing.T, withFetcher bool) {
	dockerClient, err := client.NewClientWithOpts(client.FromEnv,
		client.WithAPIVersionNegotiation())
	if err != nil {
		t.Skip("Socket "+client.DefaultDockerHost+" mandatory to run docker tests:", err.Error())
	}

	engine, err := newDockerEngine(context.Background(), slog.Default(), client.DefaultDockerHost)
	assert.NoError(t, err)

	if _, err = dockerClient.ImageInspect(context.Background(), "alpine:3.20.3"); client.IsErrNotFound(err) {
		pullRes, err := dockerClient.ImagePull(context.Background(), "alpine:3.20.3", image.PullOptions{})
		assert.NoError(t, err)

		defer pullRes.Close()
		_, err = io.Copy(io.Discard, pullRes)
		assert.NoError(t, err)
	}

	ctr, err := dockerClient.ContainerCreate(context.Background(), &container.Config{
		User:   "testuser",
		Env:    []string{"env=env"},
		Image:  "alpine:3.20.3",
		Labels: map[string]string{"foo": "bar"},
		Healthcheck: &container.HealthConfig{
			Test: []string{"CMD", "/tmp/foo", "bar"},
		},
	}, &container.HostConfig{
		Privileged: true,
		Resources: container.Resources{
			CPUQuota:   2000,
			CpusetCpus: "0-1",
		},
	}, nil, nil, "test_container")
	assert.NoError(t, err)

	imageId := "63b790fccc9078ab8bb913d94a5d869e19fca9b77712b315da3fa45bb8f14636"
	if runtime.GOARCH == "arm64" {
		imageId = "511a44083d3a23416fadc62847c45d14c25cbace86e7a72b2b350436978a0450"
	}

	expectedEvent := event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:           typeDocker.ToCTValue(),
				ID:             ctr.ID[:shortIDLength],
				Name:           "test_container",
				Image:          "alpine:3.20.3",
				ImageDigest:    "sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a",
				ImageID:        imageId,
				ImageRepo:      "alpine",
				ImageTag:       "3.20.3",
				User:           "testuser",
				CPUPeriod:      defaultCpuPeriod,
				CPUQuota:       2000,
				CPUShares:      defaultCpuShares,
				CPUSetCPUCount: 2, // 0-1
				Env:            []string{"env=env", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"},
				FullID:         ctr.ID,
				Labels:         map[string]string{"foo": "bar"},
				Privileged:     true,
				Mounts:         []event.Mount{},
				PortMappings:   []event.PortMapping{},
				Size:           -1,
				HealthcheckProbe: &event.Probe{
					Exe:  "/tmp/foo",
					Args: []string{"bar"},
				},
			}},
		IsCreate: true,
	}

	if withFetcher {
		testFetcher(t, engine, expectedEvent.ID, expectedEvent)
		err = dockerClient.ContainerRemove(context.Background(), ctr.ID, container.RemoveOptions{})
		assert.NoError(t, err)
		return
	}

	events, err := engine.List(context.Background())
	assert.NoError(t, err)
	found := false
	for _, evt := range events {
		if evt.FullID == ctr.ID {
			found = true
			// We don't have this before creation
			expectedEvent.CreatedTime = evt.CreatedTime
			assert.Equal(t, expectedEvent, evt)
		}
	}
	assert.True(t, found)

	wg := sync.WaitGroup{}
	cancelCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	listCh, err := engine.Listen(cancelCtx, &wg)

	err = dockerClient.ContainerRemove(context.Background(), ctr.ID, container.RemoveOptions{})
	assert.NoError(t, err)

	// receive the "remove" event
	expectedEvent = event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:   typeDocker.ToCTValue(),
				ID:     ctr.ID[:shortIDLength],
				FullID: ctr.ID,
				Image:  "alpine:3.20.3",
			}},
		IsCreate: false,
	}

	evt := waitOnChannelOrTimeout(t, listCh)
	assert.Equal(t, expectedEvent, evt)
}

func TestDocker(t *testing.T) {
	testDocker(t, false)
}
