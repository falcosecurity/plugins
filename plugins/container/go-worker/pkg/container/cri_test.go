package container

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	internalapi "k8s.io/cri-api/pkg/apis"
	v1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	remote "k8s.io/cri-client/pkg"
	"k8s.io/cri-client/pkg/fake"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

func TestCRIInfoMap(t *testing.T) {
	jsonInfo := `
{
"sandboxID": "7c81e23f249ed06a6a804edcc89eb74e3c44e326257d8709db3a7a74bbbd2efb",
"pid": 0,
"removing": false,
"snapshotKey": "570b00d1f91393c91dfc131d7887f37def66902e360e63a7526e7c74fae53c0d",
"snapshotter": "overlayfs",
"runtimeType": "io.containerd.runc.v2",
"runtimeOptions": null,
"config": {
  "metadata": {
	"name": "test_container"
  },
  "image": {
	"image": "alpine:3.20.3"
  },
  "envs": [
	{
	  "key": "test",
	  "value": "container"
	}
  ],
  "labels": {
	"foo": "bar"
  },
  "linux": {
	"resources": {
	  "cpu_quota": 2000,
	  "cpuset_cpus": "1-3"
	},
	"security_context": {}
  }
},
"runtimeSpec": {
  "ociVersion": "1.1.0",
  "process": {
	"user": {
	  "uid": 0,
	  "gid": 0,
	  "additionalGids": [
		0,
		1,
		2,
		3,
		4,
		6,
		10,
		11,
		20,
		26,
		27
	  ]
	},
	"args": [
	  "/bin/sh"
	],
	"env": [
	  "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	  "HOSTNAME=federico.dipierro",
	  "test=container"
	],
	"cwd": "/",
	"capabilities": {
	  "bounding": [
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FSETID",
		"CAP_FOWNER",
		"CAP_MKNOD",
		"CAP_NET_RAW",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETFCAP",
		"CAP_SETPCAP",
		"CAP_NET_BIND_SERVICE",
		"CAP_SYS_CHROOT",
		"CAP_KILL",
		"CAP_AUDIT_WRITE"
	  ],
	  "effective": [
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FSETID",
		"CAP_FOWNER",
		"CAP_MKNOD",
		"CAP_NET_RAW",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETFCAP",
		"CAP_SETPCAP",
		"CAP_NET_BIND_SERVICE",
		"CAP_SYS_CHROOT",
		"CAP_KILL",
		"CAP_AUDIT_WRITE"
	  ],
	  "permitted": [
		"CAP_CHOWN",
		"CAP_DAC_OVERRIDE",
		"CAP_FSETID",
		"CAP_FOWNER",
		"CAP_MKNOD",
		"CAP_NET_RAW",
		"CAP_SETGID",
		"CAP_SETUID",
		"CAP_SETFCAP",
		"CAP_SETPCAP",
		"CAP_NET_BIND_SERVICE",
		"CAP_SYS_CHROOT",
		"CAP_KILL",
		"CAP_AUDIT_WRITE"
	  ]
	},
	"apparmorProfile": "cri-containerd.apparmor.d",
	"oomScoreAdj": 0
  },
  "root": {
	"path": "rootfs"
  },
  "mounts": [
	{
	  "destination": "/proc",
	  "type": "proc",
	  "source": "proc",
	  "options": [
		"nosuid",
		"noexec",
		"nodev"
	  ]
	},
	{
	  "destination": "/dev",
	  "type": "tmpfs",
	  "source": "tmpfs",
	  "options": [
		"nosuid",
		"strictatime",
		"mode=755",
		"size=65536k"
	  ]
	}
  ],
  "annotations": {
	"io.kubernetes.cri.container-name": "test_container",
	"io.kubernetes.cri.container-type": "container",
	"io.kubernetes.cri.image-name": "docker.io/library/alpine:3.20.3",
	"io.kubernetes.cri.sandbox-id": "7c81e23f249ed06a6a804edcc89eb74e3c44e326257d8709db3a7a74bbbd2efb",
	"io.kubernetes.cri.sandbox-name": "test",
	"io.kubernetes.cri.sandbox-namespace": "default",
	"io.kubernetes.cri.sandbox-uid": "04688d49-005b-46ec-a200-18ed04a954fb"
  },
  "linux": {
	"resources": {
	  "devices": [
		{
		  "allow": false,
		  "access": "rwm"
		}
	  ],
	  "memory": {},
	  "cpu": {
		"quota": 2000,
		"cpus": "1-3"
	  }
	},
	"cgroupsPath": "/k8s.io/570b00d1f91393c91dfc131d7887f37def66902e360e63a7526e7c74fae53c0d",
	"namespaces": [
	  {
		"type": "pid",
		"path": "/proc/293715/ns/pid"
	  },
	  {
		"type": "ipc",
		"path": "/proc/293715/ns/ipc"
	  }
	]
  }
}
}
`
	var ctrInfo criInfo
	err := json.Unmarshal([]byte(jsonInfo), &ctrInfo)
	assert.NoError(t, err)
}

func testCRIFake(t *testing.T, withFetcher bool) {
	endpoint, err := fake.GenerateEndpoint()
	require.NoError(t, err)

	fakeRuntime := fake.NewFakeRemoteRuntime()
	err = fakeRuntime.Start(endpoint)
	assert.NoError(t, err)
	t.Cleanup(func() {
		fakeRuntime.Stop()
	})

	engine, err := newCriEngine(context.Background(), slog.Default(), endpoint)
	assert.NoError(t, err)

	id := uuid.New()
	lastAppliedConfig := `{"spec":{"containers":[{"name":"test_container","livenessProbe":{"exec":{"command":["/bin/healthcheck","--live"]}},"readinessProbe":{"exec":{"command":["/bin/healthcheck","--ready"]}}}]}}`
	podSandboxConfig := &v1.PodSandboxConfig{
		Metadata: &v1.PodSandboxMetadata{
			Name:      "test_sandbox",
			Uid:       id.String(),
			Namespace: "default",
			Attempt:   0,
		},
		Annotations: map[string]string{
			k8sLastAppliedConfigAnnotation: lastAppliedConfig,
		},
	}
	sandboxResp, err := fakeRuntime.RunPodSandbox(context.Background(), &v1.RunPodSandboxRequest{
		Config: podSandboxConfig,
	})
	assert.NoError(t, err)
	sandboxID := sandboxResp.PodSandboxId

	ctr, err := fakeRuntime.CreateContainer(context.Background(), &v1.CreateContainerRequest{
		Config: &v1.ContainerConfig{
			Metadata: &v1.ContainerMetadata{
				Name:    "test_container",
				Attempt: 0,
			},
			Image: &v1.ImageSpec{
				Image: "alpine:3.20.3",
			},
			Labels: map[string]string{"foo": "bar"},
			Envs: []*v1.KeyValue{{
				Key:   "test",
				Value: "container",
			}},
			// These won't get set by the fake implementation of cri
			Linux: &v1.LinuxContainerConfig{
				Resources: &v1.LinuxContainerResources{
					CpuQuota:   2,
					CpusetCpus: "1-3",
				},
				SecurityContext: &v1.LinuxContainerSecurityContext{
					Privileged: true,
				},
			},
		},
		PodSandboxId: sandboxID,
	})
	assert.NoError(t, err)

	// The fake runtime's BuildSandboxName generates: name_namespace_uid_attempt
	// Container ID is: sandboxID_containerName_attempt
	expectedFullID := sandboxID + "_test_container_0"
	expectedEvent := event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:             typeCri.ToCTValue(),
				ID:               shortContainerID(expectedFullID),
				Name:             "test_container",
				Image:            "alpine:3.20.3",
				ImageDigest:      "",
				ImageID:          "",
				ImageRepo:        "alpine",
				ImageTag:         "3.20.3",
				User:             "0",
				CPUPeriod:        defaultCpuPeriod,
				CPUQuota:         0,
				CPUShares:        defaultCpuShares,
				CPUSetCPUCount:   0,
				Env:              nil, // not returned in fake mode
				FullID:           expectedFullID,
				Ip:               "192.168.192.168",
				Labels: map[string]string{
					"foo":                         "bar",
					"io.kubernetes.sandbox.id":    sandboxID,
					"io.kubernetes.pod.uid":       id.String(),
					"io.kubernetes.pod.name":      "test_sandbox",
					"io.kubernetes.pod.namespace": "default",
				},
				PodSandboxID:     sandboxID,
				Privileged:       false,
				PodSandboxLabels: map[string]string{},
				Mounts:           []event.Mount{},
				Size:             -1,
				LivenessProbe: &event.Probe{
					Exe:  "/bin/healthcheck",
					Args: []string{"--live"},
				},
				ReadinessProbe: &event.Probe{
					Exe:  "/bin/healthcheck",
					Args: []string{"--ready"},
				},
			}},
		IsCreate: true,
	}

	if withFetcher {
		// FakeRuntimeService ListContainers wants the fullID:
		// https://github.com/kubernetes/cri-api/blob/master/pkg/apis/testing/fake_runtime_service.go#L469
		testFetcher(t, engine, expectedEvent.FullID, expectedEvent)
		_, err = fakeRuntime.RemoveContainer(context.Background(), &v1.RemoveContainerRequest{ContainerId: ctr.ContainerId})
		assert.NoError(t, err)
		return
	}

	events, err := engine.List(context.Background())
	assert.NoError(t, err)
	// We don't have this before creation
	found := false
	for _, evt := range events {
		if evt.FullID == ctr.ContainerId {
			found = true
			// We don't have this before creation
			expectedEvent.CreatedTime = evt.CreatedTime
			assert.Equal(t, expectedEvent, evt)
		}
	}
	assert.True(t, found)

	// fakeruntime.GetContainerEvents() returns nil. Cannot be tested.
}

func TestCRIFake(t *testing.T) {
	testCRIFake(t, false)
}

func testCRI(t *testing.T, withFetcher bool) {
	const criSocket = "/run/containerd/containerd.sock"
	client, err := remote.NewRemoteRuntimeService(criSocket, 5*time.Second, nil, nil)
	if err != nil {
		t.Skip("Socket "+criSocket+" mandatory to run cri tests:", err.Error())
	}

	engine, err := newCriEngine(context.Background(), slog.Default(), criSocket)
	assert.NoError(t, err)

	id := uuid.New()
	podSandboxConfig := &v1.PodSandboxConfig{
		Metadata: &v1.PodSandboxMetadata{
			Name:      "test",
			Uid:       id.String(),
			Namespace: "default",
			Attempt:   0,
		},
	}
	sandboxName, err := client.RunPodSandbox(context.Background(), podSandboxConfig, "")
	assert.NoError(t, err)

	// Pull image
	imageClient, err := remote.NewRemoteImageService(criSocket, 20*time.Second, nil, nil)
	assert.NoError(t, err)
	imageSpec := &v1.ImageSpec{
		Image: "alpine:3.20.3",
	}
	if _, err = imageClient.ImageStatus(context.Background(), imageSpec, false); err != nil {
		_, err = imageClient.PullImage(context.Background(), imageSpec, nil, podSandboxConfig)
		assert.NoError(t, err)
	}

	ctr, err := client.CreateContainer(context.Background(), sandboxName, &v1.ContainerConfig{
		Metadata: &v1.ContainerMetadata{
			Name:    "test_container",
			Attempt: 0,
		},
		Image: &v1.ImageSpec{
			Image: "alpine:3.20.3",
		},
		Labels: map[string]string{"foo": "bar"},
		Envs: []*v1.KeyValue{{
			Key:   "test",
			Value: "container",
		}},
		Linux: &v1.LinuxContainerConfig{
			Resources: &v1.LinuxContainerResources{
				CpuQuota:   2000,
				CpusetCpus: "1-3",
			},
			SecurityContext: &v1.LinuxContainerSecurityContext{
				Privileged: false,
			},
		},
	}, podSandboxConfig)
	assert.NoError(t, err)

	expectedEvent := event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:             typeContainerd.ToCTValue(),
				ID:               shortContainerID(ctr),
				Name:             "test_container",
				Image:            "docker.io/library/alpine:3.20.3",
				ImageDigest:      "sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a",
				ImageID:          "3.20.3",
				ImageRepo:        "docker.io/library/alpine",
				ImageTag:         "3.20.3",
				User:             "0",
				CPUPeriod:        defaultCpuPeriod,
				CPUQuota:         2000,
				CPUShares:        defaultCpuShares,
				CPUSetCPUCount:   3,
				Env:              []string{"test=container"},
				FullID:           ctr,
				Labels:           map[string]string{"foo": "bar", "io.kubernetes.sandbox.id": sandboxName, "io.kubernetes.pod.name": "test", "io.kubernetes.pod.namespace": "default", "io.kubernetes.pod.uid": id.String()},
				PodSandboxID:     sandboxName,
				Privileged:       false,
				PodSandboxLabels: map[string]string{},
				Mounts:           []event.Mount{},
				IsPodSandbox:     true,
				Size:             -1,
			}},
		IsCreate: true,
	}

	if withFetcher {
		// RuntimeService wants the short ID:
		// https://github.com/cri-o/cri-o/blob/592e805f2423ba55054a16d3a7cc66499e2c0dac/server/container_list.go#L41
		testFetcher(t, engine, expectedEvent.ID, expectedEvent)

		err = client.RemoveContainer(context.Background(), "test_sandbox_test_container_0")
		assert.NoError(t, err)

		err = client.RemovePodSandbox(context.Background(), sandboxName)
		assert.NoError(t, err)
		return
	}

	events, err := engine.List(context.Background())
	assert.NoError(t, err)
	found := false
	for _, evt := range events {
		if evt.FullID == ctr {
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

	err = client.RemoveContainer(context.Background(), "test_sandbox_test_container_0")
	assert.NoError(t, err)

	err = client.RemovePodSandbox(context.Background(), sandboxName)
	assert.NoError(t, err)

	// receive the "remove" event
	expectedEvent = event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:        typeContainerd.ToCTValue(),
				ID:          ctr[:shortIDLength],
				FullID:      ctr,
				CreatedTime: expectedEvent.CreatedTime,
			}},
		IsCreate: false,
	}
	for {
		select {
		case evt := <-listCh:
			if evt.IsCreate == false {
				assert.Equal(t, expectedEvent, evt)
				return
			}
		case <-time.After(5 * time.Second):
			t.Error("timed out waiting for channel")
			return
		}
	}
}

func TestCRI(t *testing.T) {
	testCRI(t, false)
}

// mockRuntimeService wraps a RuntimeService and allows injecting events into GetContainerEvents
type mockRuntimeService struct {
	internalapi.RuntimeService
	eventsToSend []*v1.ContainerEventResponse
}

func (m *mockRuntimeService) GetContainerEvents(ctx context.Context, containerEventsCh chan *v1.ContainerEventResponse, callback func(v1.RuntimeService_GetContainerEventsClient)) error {
	for _, evt := range m.eventsToSend {
		select {
		case containerEventsCh <- evt:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestCRIListen(t *testing.T) {
	endpoint, err := fake.GenerateEndpoint()
	require.NoError(t, err)

	fakeRuntime := fake.NewFakeRemoteRuntime()
	err = fakeRuntime.Start(endpoint)
	assert.NoError(t, err)
	t.Cleanup(func() {
		fakeRuntime.Stop()
	})

	// Create engine with fake runtime
	engine, err := newCriEngine(context.Background(), slog.Default(), endpoint)
	assert.NoError(t, err)
	criEngine := engine.(*criEngine)

	// Create a test container to get a valid container ID
	id := uuid.New()
	podSandboxConfig := &v1.PodSandboxConfig{
		Metadata: &v1.PodSandboxMetadata{
			Name:      "test_sandbox",
			Uid:       id.String(),
			Namespace: "default",
			Attempt:   0,
		},
	}
	sandboxResp, err := fakeRuntime.RunPodSandbox(context.Background(), &v1.RunPodSandboxRequest{
		Config: podSandboxConfig,
	})
	assert.NoError(t, err)

	ctr, err := fakeRuntime.CreateContainer(context.Background(), &v1.CreateContainerRequest{
		Config: &v1.ContainerConfig{
			Metadata: &v1.ContainerMetadata{
				Name:    "test_container",
				Attempt: 0,
			},
			Image: &v1.ImageSpec{
				Image: "alpine:3.20.3",
			},
		},
		PodSandboxId: sandboxResp.PodSandboxId,
	})
	assert.NoError(t, err)

	containerID := ctr.ContainerId

	tests := []struct {
		name          string
		eventType     v1.ContainerEventType
		hooks         byte
		expectEvent   bool
		validateEvent func(t *testing.T, evt event.Event, containerID string)
	}{
		{
			name:        "filters_container_stopped_events",
			eventType:   v1.ContainerEventType_CONTAINER_STOPPED_EVENT,
			hooks:       config.HookCreate | config.HookStart | config.HookRemove,
			expectEvent: false,
		},
		{
			name:        "processes_container_created_events",
			eventType:   v1.ContainerEventType_CONTAINER_CREATED_EVENT,
			hooks:       config.HookCreate | config.HookStart | config.HookRemove,
			expectEvent: true,
			validateEvent: func(t *testing.T, evt event.Event, containerID string) {
				assert.Equal(t, containerID, evt.Info.Container.FullID)
				assert.True(t, evt.IsCreate)
			},
		},
		{
			name:        "processes_container_started_events",
			eventType:   v1.ContainerEventType_CONTAINER_STARTED_EVENT,
			hooks:       config.HookCreate | config.HookStart | config.HookRemove,
			expectEvent: true,
			validateEvent: func(t *testing.T, evt event.Event, containerID string) {
				assert.Equal(t, containerID, evt.Info.Container.FullID)
				assert.True(t, evt.IsCreate)
			},
		},
		{
			name:        "processes_container_deleted_events",
			eventType:   v1.ContainerEventType_CONTAINER_DELETED_EVENT,
			hooks:       config.HookCreate | config.HookStart | config.HookRemove,
			expectEvent: true,
			validateEvent: func(t *testing.T, evt event.Event, containerID string) {
				assert.Equal(t, containerID, evt.Info.Container.FullID)
				assert.False(t, evt.IsCreate)
			},
		},
		{
			name:        "respects_hook_configuration",
			eventType:   v1.ContainerEventType_CONTAINER_CREATED_EVENT,
			hooks:       config.HookStart | config.HookRemove, // HookCreate disabled
			expectEvent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set hook configuration for this test
			config.Load(fmt.Sprintf(`{"hooks": %d}`, tt.hooks))

			mockClient := &mockRuntimeService{
				RuntimeService: criEngine.client,
				eventsToSend: []*v1.ContainerEventResponse{{
					ContainerId:        containerID,
					ContainerEventType: tt.eventType,
					CreatedAt:          time.Now().UnixNano(),
				}},
			}
			criEngine.client = mockClient

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			wg := sync.WaitGroup{}
			outCh, err := criEngine.Listen(ctx, &wg)
			assert.NoError(t, err)

			if tt.expectEvent {
				// Verify an event was produced
				select {
				case evt, ok := <-outCh:
					if !ok {
						t.Error("Channel closed unexpectedly")
						return
					}
					if evt.Info.Container.FullID == "" {
						t.Error("Received zero-value event")
						return
					}
					if tt.validateEvent != nil {
						tt.validateEvent(t, evt, containerID)
					}
				case <-time.After(1 * time.Second):
					t.Error("Timeout waiting for event")
				}
			} else {
				// Verify no event was produced
				select {
				case evt, ok := <-outCh:
					if ok && evt.Info.Container.FullID != "" {
						t.Errorf("Unexpected event produced: %+v", evt)
					}
					// If !ok, channel was closed (expected) or zero-value from closed channel
				case <-time.After(1 * time.Second):
					// Expected: no event should be produced
				}
			}

			cancel()
			wg.Wait()
		})
	}
}
