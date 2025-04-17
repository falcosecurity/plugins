//go:build linux

package container

import (
	"context"
	"fmt"
	"github.com/containers/image/v5/manifest"
	"github.com/containers/podman/v5/pkg/bindings"
	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/bindings/images"
	"github.com/containers/podman/v5/pkg/specgen"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"os/user"
	"runtime"
	"sync"
	"testing"
	"time"
)

func waitOnChannelOrTimeout(t *testing.T, ch <-chan event.Event) event.Event {
	select {
	case ret := <-ch:
		return ret
	case <-time.After(5 * time.Second):
		t.Error("timed out waiting for channel")
	}
	return event.Event{}
}

func testPodman(t *testing.T, withFetcher bool) {
	usr, err := user.Current()
	assert.NoError(t, err)

	var podmanSocket string
	if usr.Name != "root" {
		podmanSocket = "/run/user/" + usr.Uid + "/podman/podman.sock"
	} else {
		podmanSocket = fmt.Sprintf("/run/podman/podman.sock")
	}

	podmanCtx, err := bindings.NewConnection(context.Background(), enforceUnixProtocolIfEmpty(podmanSocket))
	if err != nil {
		t.Skip("Socket "+podmanSocket+" mandatory to run podman tests:", err.Error())
	}

	if _, err = images.GetImage(podmanCtx, "alpine:3.20.3", nil); err != nil {
		_, err = images.Pull(podmanCtx, "alpine:3.20.3", nil)
		assert.NoError(t, err)
	}

	engine, err := newPodmanEngine(context.Background(), podmanSocket)
	assert.NoError(t, err)

	privileged := true
	var cpuQuota int64 = 2000
	ctr, err := containers.CreateWithSpec(podmanCtx, &specgen.SpecGenerator{
		ContainerBasicConfig: specgen.ContainerBasicConfig{
			Name:   "test_container",
			Env:    map[string]string{"env": "env"},
			Labels: map[string]string{"foo": "bar"},
		},
		ContainerStorageConfig: specgen.ContainerStorageConfig{
			Image: "alpine:3.20.3",
		},
		ContainerSecurityConfig: specgen.ContainerSecurityConfig{
			Privileged: &privileged,
			User:       "testuser",
		},
		ContainerResourceConfig: specgen.ContainerResourceConfig{
			ResourceLimits: &specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Quota: &cpuQuota,
					Cpus:  "0-1",
				},
			},
		},
		ContainerHealthCheckConfig: specgen.ContainerHealthCheckConfig{
			HealthConfig: &manifest.Schema2HealthConfig{
				Test: []string{"CMD-SHELL", "echo hello world"},
			},
		},
	}, nil)
	assert.NoError(t, err)

	imageId := "63b790fccc9078ab8bb913d94a5d869e19fca9b77712b315da3fa45bb8f14636"
	if runtime.GOARCH == "arm64" {
		imageId = "511a44083d3a23416fadc62847c45d14c25cbace86e7a72b2b350436978a0450"
	}

	expectedEvent := event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:           typePodman.ToCTValue(),
				ID:             shortContainerID(ctr.ID),
				Name:           "test_container",
				Image:          "docker.io/library/alpine:3.20.3",
				ImageDigest:    "sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a",
				ImageID:        imageId,
				ImageRepo:      "docker.io/library/alpine",
				ImageTag:       "3.20.3",
				User:           "testuser",
				CPUPeriod:      defaultCpuPeriod,
				CPUQuota:       2000,
				CPUShares:      defaultCpuShares,
				CPUSetCPUCount: 2, // 0-1
				FullID:         ctr.ID,
				Labels:         map[string]string{"foo": "bar"},
				Privileged:     true,
				Mounts:         []event.Mount{},
				PortMappings:   []event.PortMapping{},
				Size:           -1,
				HealthcheckProbe: &event.Probe{
					Exe:  "/bin/sh",
					Args: []string{"-c", "echo hello world"},
				},
			}},
		IsCreate: true,
	}

	if withFetcher {
		testFetcher(t, engine, expectedEvent.ID, expectedEvent)
		_, err = containers.Remove(podmanCtx, ctr.ID, nil)
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
			assert.Contains(t, evt.Env, "env=env")
			expectedEvent.Env = evt.Env
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

	// Give some time to podman Listen to start up its goroutines
	time.Sleep(1 * time.Second)

	_, err = containers.Remove(podmanCtx, ctr.ID, nil)
	assert.NoError(t, err)

	// receive the "remove" event
	expectedEvent = event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:   typePodman.ToCTValue(),
				ID:     shortContainerID(ctr.ID),
				FullID: ctr.ID,
				Image:  "docker.io/library/alpine:3.20.3",
			}},
		IsCreate: false,
	}
	evt := waitOnChannelOrTimeout(t, listCh)
	assert.Equal(t, expectedEvent, evt)
}

func TestPodman(t *testing.T) {
	testPodman(t, false)
}
