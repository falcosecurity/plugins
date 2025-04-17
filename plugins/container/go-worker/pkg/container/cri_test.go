package container

import (
	"context"
	"encoding/json"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	remote "k8s.io/cri-client/pkg"
	"k8s.io/cri-client/pkg/fake"
	"sync"
	"testing"
	"time"
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

	engine, err := newCriEngine(context.Background(), endpoint)
	assert.NoError(t, err)

	id := uuid.New()
	podSandboxConfig := &v1.PodSandboxConfig{
		Metadata: &v1.PodSandboxMetadata{
			Name:      "test_sandbox",
			Uid:       id.String(),
			Namespace: "default",
			Attempt:   0,
		},
	}
	_, err = fakeRuntime.RunPodSandbox(context.Background(), &v1.RunPodSandboxRequest{
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
		PodSandboxId: "test_sandbox",
	})
	assert.NoError(t, err)

	expectedEvent := event.Event{
		Info: event.Info{
			Container: event.Container{
				Type:             typeCri.ToCTValue(),
				ID:               "test_sandbox",
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
				FullID:           "test_sandbox_test_container_0",
				Labels:           map[string]string{"foo": "bar", "io.kubernetes.sandbox.id": "test_sandbox_test_container_0"},
				PodSandboxID:     "test_sandbox_test_container_0",
				Privileged:       false,
				PodSandboxLabels: map[string]string{},
				Mounts:           []event.Mount{},
				Size:             -1,
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

	engine, err := newCriEngine(context.Background(), criSocket)
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
		evt := waitOnChannelOrTimeout(t, listCh)
		if evt.IsCreate == false {
			assert.Equal(t, expectedEvent, evt)
			break
		}
	}
}

func TestCRI(t *testing.T) {
	testCRI(t, false)
}
