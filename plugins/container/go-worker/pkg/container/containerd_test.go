package container

import (
	"context"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"github.com/google/uuid"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/assert"
	"os/user"
	"sync"
	"testing"
)

func testContainerd(t *testing.T, withFetcher bool) {
	usr, err := user.Current()
	assert.NoError(t, err)
	if usr.Uid != "0" {
		t.Skip("Containerd test requires root user")
	}

	const containerdSocket = "/run/containerd/containerd.sock"
	client, err := containerd.New(containerdSocket)
	if err != nil {
		t.Skip("Socket "+containerdSocket+" mandatory to run containerd tests:", err.Error())
	}

	engine, err := newContainerdEngine(context.Background(), containerdSocket)
	assert.NoError(t, err)

	namespacedCtx := namespaces.WithNamespace(context.Background(), "test_ns")

	// Pull image
	if _, err = client.GetImage(namespacedCtx, "docker.io/library/alpine:3.20.3"); err != nil {
		_, err = client.Pull(namespacedCtx, "docker.io/library/alpine:3.20.3")
		assert.NoError(t, err)
	}

	id := uuid.New()
	var cpuQuota int64 = 2000
	ctr, err := client.NewContainer(namespacedCtx, id.String(), containerd.WithImageName("docker.io/library/alpine:3.20.3"),
		containerd.WithSpec(
			&oci.Spec{
				Process: &specs.Process{
					User: specs.User{
						UID: 0,
						GID: 0,
					},
				},
				Linux: &specs.Linux{
					Resources: &specs.LinuxResources{
						CPU: &specs.LinuxCPU{
							Quota: &cpuQuota,
							Cpus:  "0-1",
						},
					},
				},
			},
			oci.WithHostNamespace(specs.NetworkNamespace),
			oci.WithLinuxNamespace(specs.LinuxNamespace{
				Type: specs.PIDNamespace,
				Path: "/proc/foo",
			}),
			oci.WithLinuxNamespace(specs.LinuxNamespace{
				Type: specs.IPCNamespace,
				Path: "/proc/foo",
			}),
			oci.WithPrivileged))
	assert.NoError(t, err)

	expectedEvent := event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:             typeContainerd.ToCTValue(),
				ID:               shortContainerID(ctr.ID()),
				Name:             shortContainerID(ctr.ID()),
				Image:            "docker.io/library/alpine:3.20.3",
				ImageRepo:        "docker.io/library/alpine",
				ImageTag:         "3.20.3",
				ImageDigest:      "sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a",
				CPUPeriod:        defaultCpuPeriod,
				CPUQuota:         cpuQuota,
				CPUShares:        defaultCpuShares,
				CPUSetCPUCount:   2, // 0-1
				Env:              nil,
				FullID:           ctr.ID(),
				HostIPC:          false,
				HostPID:          false,
				HostNetwork:      true,
				Labels:           map[string]string{},
				PodSandboxID:     "",
				Privileged:       true,
				PodSandboxLabels: nil,
				Mounts:           []event.Mount{},
				User:             "0",
				Size:             -1,
			}},
		IsCreate: true,
	}

	if withFetcher {
		testFetcher(t, engine, expectedEvent.ID, expectedEvent)
		err = ctr.Delete(namespacedCtx)
		assert.NoError(t, err)
		return
	}

	events, err := engine.List(context.Background())
	assert.NoError(t, err)
	found := false
	for _, evt := range events {
		if evt.FullID == ctr.ID() {
			found = true
			// We don't have these before creation
			expectedEvent.CreatedTime = evt.CreatedTime
			expectedEvent.Ip = evt.Ip
			assert.Equal(t, expectedEvent, evt)
		}
	}
	assert.True(t, found)

	// Now try the listen API
	wg := sync.WaitGroup{}
	cancelCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		wg.Wait()
	})

	listCh, err := engine.Listen(cancelCtx, &wg)
	assert.NoError(t, err)

	err = ctr.Delete(namespacedCtx)
	assert.NoError(t, err)

	expectedEvent = event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:   typeContainerd.ToCTValue(),
				ID:     shortContainerID(ctr.ID()),
				FullID: ctr.ID(),
			}},
		IsCreate: false,
	}

	// receive the "remove" event
	evt := waitOnChannelOrTimeout(t, listCh)
	assert.Equal(t, expectedEvent, evt)
}

func TestContainerd(t *testing.T) {
	testContainerd(t, false)
}
