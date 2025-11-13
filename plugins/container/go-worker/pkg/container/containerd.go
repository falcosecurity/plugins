package container

import (
	"context"
	"strconv"
	"strings"
	"sync"

	"github.com/containerd/containerd/api/events"
	containerd "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/containers"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"github.com/containerd/containerd/v2/pkg/oci"
	"github.com/containerd/typeurl/v2"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"github.com/opencontainers/runtime-spec/specs-go"
)

func init() {
	engineGenerators[typeContainerd] = newContainerdEngine
}

type containerdEngine struct {
	client *containerd.Client
	socket string
}

func newContainerdEngine(_ context.Context, socket string) (Engine, error) {
	client, err := containerd.New(socket)
	if err != nil {
		return nil, err
	}
	return &containerdEngine{client: client, socket: socket}, nil
}

func (c *containerdEngine) copy(ctx context.Context) (Engine, error) {
	return newContainerdEngine(ctx, c.socket)
}

func (c *containerdEngine) ctrToInfo(namespacedContext context.Context, container containerd.Container) event.Info {
	info, err := container.Info(namespacedContext)
	if err != nil {
		info = containers.Container{}
	}
	spec, err := container.Spec(namespacedContext)
	if err != nil {
		spec = &oci.Spec{
			Process: &specs.Process{},
			Mounts:  nil,
		}
	}

	// Name related
	var containerName string
	if name, ok := spec.Annotations["io.kubernetes.cri.container-name"]; ok && name != "" {
		containerName = name
	} else {
		containerName = shortContainerID(container.ID())
	}

	// Cpu related
	var (
		cpuPeriod   uint64 = defaultCpuPeriod
		cpuQuota    int64
		cpuShares   uint64 = defaultCpuShares
		cpusetCount int64
	)
	if spec.Linux != nil && spec.Linux.Resources != nil && spec.Linux.Resources.CPU != nil {
		if spec.Linux.Resources.CPU.Period != nil && *spec.Linux.Resources.CPU.Period > 0 {
			cpuPeriod = *spec.Linux.Resources.CPU.Period
		}
		if spec.Linux.Resources.CPU.Quota != nil {
			cpuQuota = *spec.Linux.Resources.CPU.Quota
		}
		if spec.Linux.Resources.CPU.Shares != nil && *spec.Linux.Resources.CPU.Shares > 0 {
			cpuShares = *spec.Linux.Resources.CPU.Shares
		}
		cpusetCount = countCPUSet(spec.Linux.Resources.CPU.Cpus)
	}

	// Mem related
	var (
		memoryLimit int64
		swapLimit   int64
	)
	if spec.Linux != nil && spec.Linux.Resources != nil && spec.Linux.Resources.Memory != nil {
		if spec.Linux.Resources.Memory.Limit != nil {
			memoryLimit = *spec.Linux.Resources.Memory.Limit
		}
		if spec.Linux.Resources.Memory.Swap != nil {
			swapLimit = *spec.Linux.Resources.Memory.Swap
		}
	}

	// Mounts related
	mounts := make([]event.Mount, 0)
	for _, m := range spec.Mounts {
		readOnly := false
		mode := ""

		for _, opt := range m.Options {
			if opt == "ro" {
				readOnly = true
			} else if strings.HasPrefix(opt, "mode=") {
				mode = strings.TrimPrefix(opt, "mode=")
			}
		}
		mounts = append(mounts, event.Mount{
			Source:      m.Source,
			Destination: m.Destination,
			Mode:        mode,
			RW:          !readOnly,
			Propagation: spec.Linux.RootfsPropagation,
		})
	}

	// Namespace related - see oci.WithHostNamespace() impl: it just removes the namespace from the list
	var (
		hostIPC     = true
		hostPID     = true
		hostNetwork = true
	)
	if spec.Linux != nil {
		for _, ns := range spec.Linux.Namespaces {
			if ns.Type == specs.PIDNamespace {
				hostPID = false
			}
			if ns.Type == specs.NetworkNamespace {
				hostNetwork = false
			}
			if ns.Type == specs.IPCNamespace {
				hostIPC = false
			}
		}
	}

	// Image related
	// FIXME: with docker, everything is empty because container.Image below does not return any image.
	var (
		imageDigest string
		imageRepo   string
		imageTag    string
		imageSize   int64 = -1
	)
	// TODO this is an extra API call; shall we move it behing config.GetWithSize()?
	// Or rename `with_size` option with something more generic like `full_info`?
	image, _ := container.Image(namespacedContext)
	if image != nil {
		imageDigest = image.Target().Digest.String()
		if config.GetWithSize() {
			imageSize = image.Target().Size
		}
	}
	imageRepoTag := strings.Split(info.Image, ":")
	if len(imageRepoTag) == 2 {
		imageRepo = imageRepoTag[0]
		imageTag = imageRepoTag[1]
	}

	// Network related - TODO

	labels := make(map[string]string)
	for key, val := range info.Labels {
		if len(val) <= config.GetLabelMaxLen() {
			labels[key] = val
		}
	}

	// if empty, try getting it from annotations
	if info.SandboxID == "" {
		if sandboxId, ok := spec.Annotations["io.kubernetes.cri.sandbox-id"]; ok {
			info.SandboxID = sandboxId
		}
	}

	isPodSandbox := info.Labels["io.cri-containerd.kind"] == "sandbox"

	var podSandboxLabels map[string]string
	sandbox, _ := c.client.LoadSandbox(namespacedContext, info.SandboxID)
	if sandbox != nil {
		sandboxLabels, _ := sandbox.Labels(namespacedContext)
		if len(sandboxLabels) > 0 {
			podSandboxLabels = make(map[string]string)
			for key, val := range sandboxLabels {
				if len(val) <= config.GetLabelMaxLen() {
					podSandboxLabels[key] = val
				}
			}
		}
	}

	// Check for privileged:
	// see https://github.com/containerd/containerd/blob/main/pkg/oci/spec_opts.go#L1295
	privileged := true
	if spec.Linux != nil && spec.Process != nil &&
		spec.Linux.MaskedPaths == nil && spec.Linux.ReadonlyPaths == nil &&
		spec.Process.SelinuxLabel == "" &&
		(spec.Process.ApparmorProfile == "" || spec.Process.ApparmorProfile == "unconfined") &&
		spec.Linux.Seccomp == nil {
		for _, m := range spec.Mounts {
			if m.Type == "sysfs" || m.Type == "cgroup" {
				for _, o := range m.Options {
					if o == "ro" {
						privileged = false
						break
					}
				}
			}
		}
	} else {
		privileged = false
	}

	return event.Info{
		Container: event.Container{
			Type:             typeContainerd.ToCTValue(),
			ID:               shortContainerID(container.ID()),
			Name:             containerName,
			Image:            info.Image,
			ImageDigest:      imageDigest,
			ImageRepo:        imageRepo,
			ImageTag:         imageTag,
			User:             strconv.FormatUint(uint64(spec.Process.User.UID), 10),
			CPUPeriod:        int64(cpuPeriod),
			CPUQuota:         cpuQuota,
			CPUShares:        int64(cpuShares),
			CPUSetCPUCount:   cpusetCount,
			CreatedTime:      info.CreatedAt.Unix(),
			Env:              spec.Process.Env,
			FullID:           container.ID(),
			HostIPC:          hostIPC,
			HostNetwork:      hostNetwork,
			HostPID:          hostPID,
			Ip:               "", // TODO
			IsPodSandbox:     isPodSandbox,
			Labels:           labels,
			MemoryLimit:      memoryLimit,
			SwapLimit:        swapLimit,
			PodSandboxID:     info.SandboxID,
			Privileged:       privileged,
			PodSandboxLabels: podSandboxLabels,
			Mounts:           mounts,
			Size:             imageSize,
		},
	}
}

func (c *containerdEngine) get(ctx context.Context, containerId string) (*event.Event, error) {
	namespacesList, err := c.client.NamespaceService().List(ctx)
	if err != nil {
		return nil, err
	}
	for _, namespace := range namespacesList {
		namespacedContext := namespaces.WithNamespace(ctx, namespace)
		container, err := c.client.LoadContainer(namespacedContext, containerId)
		if err == nil {
			return &event.Event{
				Info:     c.ctrToInfo(namespacedContext, container),
				IsCreate: true,
			}, nil
		}
	}
	return nil, nil
}

func (c *containerdEngine) Name() string {
	return string(typeContainerd)
}

func (c *containerdEngine) Sock() string {
	return c.socket
}

func (c *containerdEngine) List(ctx context.Context) ([]event.Event, error) {
	namespacesList, err := c.client.NamespaceService().List(ctx)
	if err != nil {
		return nil, err
	}
	evts := make([]event.Event, 0)
	for _, namespace := range namespacesList {
		namespacedContext := namespaces.WithNamespace(ctx, namespace)
		containersList, err := c.client.Containers(namespacedContext)
		if err != nil {
			continue
		}
		for _, container := range containersList {
			evts = append(evts, event.Event{
				Info:     c.ctrToInfo(namespacedContext, container),
				IsCreate: true,
			})
		}
	}
	return evts, nil
}

func (c *containerdEngine) Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error) {
	outCh := make(chan event.Event)
	eventsClient := c.client.EventService()

	topics := make([]string, 0)
	if config.IsHookEnabled(config.HookCreate) {
		topics = append(topics, `topic=="/containers/create"`)
	}
	if config.IsHookEnabled(config.HookStart) {
		topics = append(topics, `topic=="/tasks/start"`)
	}
	if config.IsHookEnabled(config.HookRemove) {
		topics = append(topics, `topic=="/containers/delete"`)
	}

	eventsCh, _ := eventsClient.Subscribe(ctx, topics...)
	wg.Add(1)
	go func() {
		defer close(outCh)
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-eventsCh:
				if !ok {
					// eventsCh has been closed - kill the goroutine
					return
				}
				if ev == nil {
					// Nothing to do for null event
					break
				}
				var (
					id       string
					isCreate bool
					image    string
					info     event.Info
				)
				switch ev.Topic {
				case "/containers/create":
					ctrCreate := events.ContainerCreate{}
					_ = typeurl.UnmarshalTo(ev.Event, &ctrCreate)
					id = ctrCreate.ID
					isCreate = true
					image = ctrCreate.Image
				case "/tasks/start":
					ctrStart := events.TaskStart{}
					_ = typeurl.UnmarshalTo(ev.Event, &ctrStart)
					id = ctrStart.ContainerID
					isCreate = true
				case "/containers/delete":
					ctrDelete := events.ContainerDelete{}
					_ = typeurl.UnmarshalTo(ev.Event, &ctrDelete)
					id = ctrDelete.ID
					isCreate = false
				}
				namespacedContext := namespaces.WithNamespace(ctx, ev.Namespace)
				container, err := c.client.LoadContainer(namespacedContext, id)
				if err != nil {
					// minimum set of infos - either for containers/delete
					// or for other hooks but with an error.
					info = event.Info{
						Container: event.Container{
							Type:   typeContainerd.ToCTValue(),
							ID:     shortContainerID(id),
							FullID: id,
							Image:  image,
						},
					}
				} else {
					info = c.ctrToInfo(namespacedContext, container)
				}
				outCh <- event.Event{
					Info:     info,
					IsCreate: isCreate,
				}
			}
		}
	}()
	return outCh, nil
}
