package container

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	internalapi "k8s.io/cri-api/pkg/apis"
	v1 "k8s.io/cri-api/pkg/apis/runtime/v1"
	remote "k8s.io/cri-client/pkg"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxCNILen = 4096

func init() {
	engineGenerators[typeCri] = newCriEngine
}

type criEngine struct {
	client  internalapi.RuntimeService
	runtime int // as CT_FOO value
	socket  string
}

// See https://github.com/falcosecurity/libs/blob/4d04cad02cd27e53cb18f431361a4d031836bb75/userspace/libsinsp/cri.hpp#L71
func getRuntime(runtime string) int {
	if runtime == "containerd" || runtime == "cri-o" {
		tp := engineType(runtime)
		return tp.ToCTValue()
	}
	return typeCri.ToCTValue()
}

func newCriEngine(ctx context.Context, socket string) (Engine, error) {
	client, err := remote.NewRemoteRuntimeService(socket, 5*time.Second, nil, nil)
	if err != nil {
		return nil, err
	}
	version, err := client.Version(ctx, "")
	if err != nil {
		return nil, err
	}
	return &criEngine{
		client:  client,
		runtime: getRuntime(version.RuntimeName),
		socket:  socket,
	}, nil
}

func (c *criEngine) copy(ctx context.Context) (Engine, error) {
	return newCriEngine(ctx, c.socket)
}

// Structures that maps container.Info() map
type criInfo struct {
	Privileged *bool `json:"privileged"`
	Config     *struct {
		Image *struct {
			Image string `json:"image"`
		} `json:"image"`
		Envs []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"envs"`
		Linux *struct {
			SecurityContext *struct {
				Privileged *bool `json:"privileged"`
			} `json:"security_context"`
		} `json:"linux"`
	} `json:"config"`
	RuntimeSpec *struct {
		Annotations map[string]string `json:"annotations"`
		Linux       *struct {
			SecurityContext *struct {
				Privileged *bool `json:"privileged"`
			} `json:"security_context"`
		} `json:"linux"`
	} `json:"runtimeSpec"`
}

func (info *criInfo) getPrivileged() bool {
	if info.RuntimeSpec != nil &&
		info.RuntimeSpec.Linux != nil &&
		info.RuntimeSpec.Linux.SecurityContext != nil &&
		info.RuntimeSpec.Linux.SecurityContext.Privileged != nil {
		return *info.RuntimeSpec.Linux.SecurityContext.Privileged
	}

	if info.Config != nil &&
		info.Config.Linux != nil &&
		info.Config.Linux.SecurityContext != nil &&
		info.Config.Linux.SecurityContext.Privileged != nil {
		return *info.Config.Linux.SecurityContext.Privileged
	}

	if info.Privileged != nil {
		return *info.Privileged
	}

	return false
}

func (info *criInfo) getEnvs() []string {
	var env []string

	if info.Config != nil &&
		info.Config.Envs != nil {
		for _, e := range info.Config.Envs {
			env = append(env, fmt.Sprintf("%s=%s", e.Key, e.Value))
		}
	}
	return env
}

func (info *criInfo) getAnnotation(key string) (string, bool) {
	if info.RuntimeSpec != nil {
		val, ok := info.RuntimeSpec.Annotations[key]
		return val, ok
	}
	return "", false
}

func (info *criInfo) getImage() string {
	if info.Config != nil &&
		info.Config.Image != nil {
		return info.Config.Image.Image
	}
	return ""
}

type CNIInterface struct {
	Name       string  `json:"name"`
	MTU        uint    `json:"mtu"`
	SocketPath *string `json:"socketPath"`
	PciID      *string `json:"pciID"`
}
type cniSandboxInfo struct {
	CNIResult *struct {
		Interfaces []*CNIInterface `json:"interfaces"`
	} `json:"cniResult"`
	RuntimeSpec *struct {
		Annotations map[string]string `json:"annotations"`
	} `json:"runtimeSpec"`
}

func (c *criEngine) ctrToInfo(ctx context.Context, ctr *v1.ContainerStatus, podSandboxStatus *v1.PodSandboxStatus,
	info map[string]string, sandboxInfo map[string]string) event.Info {

	var ctrInfo criInfo
	jsonInfo, present := info["info"]
	if present {
		_ = json.Unmarshal([]byte(jsonInfo), &ctrInfo)
	}

	// Cpu related
	var (
		cpuPeriod   int64 = defaultCpuPeriod
		cpuQuota    int64
		cpuShares   int64 = defaultCpuShares
		cpusetCount int64
	)
	// Memory related
	var (
		memoryLimit int64
		swapLimit   int64
	)
	if ctr.GetResources().GetLinux() != nil {
		if ctr.GetResources().GetLinux().CpuPeriod > 0 {
			cpuPeriod = ctr.GetResources().GetLinux().CpuPeriod
		}
		cpuQuota = ctr.GetResources().GetLinux().CpuQuota
		if ctr.GetResources().GetLinux().CpuShares > 0 {
			cpuShares = ctr.GetResources().GetLinux().CpuShares
		}
		cpusetCount = countCPUSet(ctr.GetResources().GetLinux().CpusetCpus)

		memoryLimit = ctr.GetResources().GetLinux().MemoryLimitInBytes
		swapLimit = ctr.GetResources().GetLinux().MemorySwapLimitInBytes
	}

	mounts := make([]event.Mount, 0)
	for _, m := range ctr.Mounts {
		var propagation string
		switch m.Propagation {
		case v1.MountPropagation_PROPAGATION_PRIVATE:
			propagation = "private"
		case v1.MountPropagation_PROPAGATION_HOST_TO_CONTAINER:
			propagation = "rslave"
		case v1.MountPropagation_PROPAGATION_BIDIRECTIONAL:
			propagation = "rshared"
		default:
			propagation = "unknown"
		}
		mounts = append(mounts, event.Mount{
			Source:      m.HostPath,
			Destination: m.ContainerPath,
			RW:          !m.Readonly,
			Propagation: propagation,
		})
	}

	isPodSandbox := podSandboxStatus != nil
	podSandboxID := ctr.Id
	if podSandboxStatus == nil {
		podSandboxStatus = &v1.PodSandboxStatus{
			Network: &v1.PodSandboxNetworkStatus{},
			Linux: &v1.LinuxPodSandboxStatus{
				Namespaces: &v1.Namespace{
					Options: &v1.NamespaceOption{},
				},
			},
		}
	} else {
		podSandboxID = podSandboxStatus.Id
	}

	var cniJson string
	var cniInfo cniSandboxInfo
	jsonInfo, present = sandboxInfo["info"]
	if present {
		err := json.Unmarshal([]byte(jsonInfo), &cniInfo)
		if err == nil {
			if cniInfo.CNIResult != nil && cniInfo.CNIResult.Interfaces != nil {
				ifaces := make([]*CNIInterface, 0)
				for _, iface := range cniInfo.CNIResult.Interfaces {
					if iface.Name != "lo" && iface.Name != "veth" {
						ifaces = append(ifaces, iface)
					}
				}
				bytes, err := json.Marshal(ifaces)
				if err != nil {
					cniJson = string(bytes)
				}
			} else if val, ok := cniInfo.RuntimeSpec.Annotations["io.kubernetes.cri-o.CNIResult"]; ok {
				cniJson = val
			}

			if len(cniJson) > maxCNILen {
				cniJson = cniJson[:maxCNILen]
			}
		}
	}

	labels := make(map[string]string)
	for key, val := range ctr.Labels {
		if len(val) <= config.GetLabelMaxLen() {
			labels[key] = val
		}
	}
	labels["io.kubernetes.sandbox.id"] = podSandboxID
	if podSandboxStatus.Metadata != nil {
		labels["io.kubernetes.pod.uid"] = podSandboxStatus.Metadata.Uid
		labels["io.kubernetes.pod.name"] = podSandboxStatus.Metadata.Name
		labels["io.kubernetes.pod.namespace"] = podSandboxStatus.Metadata.Namespace
	}

	podSandboxLabels := make(map[string]string)
	for key, val := range podSandboxStatus.Labels {
		if len(val) <= config.GetLabelMaxLen() {
			podSandboxLabels[key] = val
		}
	}

	var size int64 = -1
	if config.GetWithSize() {
		stats, _ := c.client.ContainerStats(ctx, ctr.Id)
		if stats != nil {
			size = int64(stats.GetWritableLayer().GetUsedBytes().GetValue())
		}
	}

	// image_ref may be one of two forms:
	// host/image@sha256:digest
	// sha256:digest
	// See https://github.com/therealbobo/libs/blob/8267fbb909167541c7f7ed655c93a7dc0c1d615b/userspace/libsinsp/cri.hpp#L320
	// for the original c++ implementation.
	imageName := ctr.GetImage().GetImage()
	imageRef := ctr.GetImageRef()
	var (
		imageRepo   string
		imageTag    string
		imageID     string
		imageDigest string
	)
	getTagFromImage := false
	digestStart := strings.Index(imageRef, "sha256:")
	switch digestStart {
	case 0: // sha256:digest
		imageDigest = imageRef
	case -1:
		break
	default: // host/image@sha256:digest
		if imageRef[digestStart-1] == '@' {
			imageName = imageRef[:digestStart-1]
			imageDigest = imageRef[digestStart:]
			getTagFromImage = true
		}
	}

	if imageName == "" || strings.HasPrefix(imageName, "sha256") {
		var (
			present bool
			val     string
		)
		if val, present = ctrInfo.getAnnotation("io.kubernetes.cri.image-name"); !present {
			if val, present = ctrInfo.getAnnotation("io.kubernetes.cri-o.Image"); !present {
				val, present = ctrInfo.getAnnotation("io.kubernetes.cri-o.ImageName")
			}
		}
		if present {
			imageName = val
			getTagFromImage = false
		}
	}

	imageRepoTag := strings.Split(imageName, ":")
	imageRepo = imageRepoTag[0]
	if len(imageRepoTag) == 2 {
		imageTag = imageRepoTag[1]
	}

	if getTagFromImage {
		imageRepoTag = strings.Split(ctr.GetImage().GetImage(), ":")
		if len(imageRepoTag) == 2 {
			imageTag = imageRepoTag[1]
			imageName += ":" + imageTag
		}
	}

	imageStr := ctrInfo.getImage()
	imageStrs := strings.Split(imageStr, ":")
	if len(imageStrs) == 2 {
		imageID = imageStrs[1]
	} else {
		imageID = imageStr
	}
	if imageID == "" {
		imageID = ctr.GetImageId()
	}

	return event.Info{
		Container: event.Container{
			Type:             c.runtime,
			ID:               shortContainerID(ctr.Id),
			Name:             ctr.GetMetadata().GetName(),
			Image:            imageName,
			ImageDigest:      imageDigest,
			ImageID:          imageID,
			ImageRepo:        imageRepo,
			ImageTag:         imageTag,
			User:             strconv.FormatInt(ctr.GetUser().GetLinux().GetUid(), 10),
			CniJson:          cniJson,
			CPUPeriod:        cpuPeriod,
			CPUQuota:         cpuQuota,
			CPUShares:        cpuShares,
			CPUSetCPUCount:   cpusetCount,
			CreatedTime:      nanoSecondsToUnix(ctr.CreatedAt),
			Env:              ctrInfo.getEnvs(),
			FullID:           ctr.Id,
			HostIPC:          podSandboxStatus.Linux.Namespaces.Options.Ipc == v1.NamespaceMode_NODE,
			HostNetwork:      podSandboxStatus.Linux.Namespaces.Options.Network == v1.NamespaceMode_NODE,
			HostPID:          podSandboxStatus.Linux.Namespaces.Options.Pid == v1.NamespaceMode_NODE,
			Ip:               podSandboxStatus.Network.Ip,
			IsPodSandbox:     isPodSandbox,
			Labels:           labels,
			MemoryLimit:      memoryLimit,
			SwapLimit:        swapLimit,
			PodSandboxID:     podSandboxID,
			Privileged:       ctrInfo.getPrivileged(),
			PodSandboxLabels: podSandboxLabels,
			Mounts:           mounts,
			Size:             size,
		},
	}
}

func (c *criEngine) get(ctx context.Context, containerId string) (*event.Event, error) {
	ctrs, err := c.client.ListContainers(ctx, &v1.ContainerFilter{Id: containerId})
	if err != nil || len(ctrs) == 0 {
		return nil, err
	}
	ctr := ctrs[0]
	container, err := c.client.ContainerStatus(ctx, ctr.Id, true)
	if err == nil {
		podSandboxStatus, _ := c.client.PodSandboxStatus(ctx, ctr.GetPodSandboxId(), false)
		if podSandboxStatus == nil {
			podSandboxStatus = &v1.PodSandboxStatusResponse{}
		}
		return &event.Event{
			IsCreate: true,
			Info:     c.ctrToInfo(ctx, container.Status, podSandboxStatus.GetStatus(), container.GetInfo(), podSandboxStatus.GetInfo()),
		}, nil
	}
	return nil, nil
}

func (c *criEngine) Name() string {
	return string(typeCri)
}

func (c *criEngine) Sock() string {
	return c.socket
}

func (c *criEngine) List(ctx context.Context) ([]event.Event, error) {
	ctrs, err := c.client.ListContainers(ctx, nil)
	if err != nil {
		return nil, err
	}
	evts := make([]event.Event, len(ctrs))
	for idx, ctr := range ctrs {
		// verbose true to return container.Info
		container, err := c.client.ContainerStatus(ctx, ctr.Id, true)
		if err != nil || container.Status == nil {
			evts[idx] = event.Event{
				IsCreate: true,
				Info: event.Info{
					Container: event.Container{
						Type:        c.runtime,
						ID:          shortContainerID(ctr.Id),
						FullID:      ctr.Id,
						ImageID:     ctr.ImageId,
						CreatedTime: nanoSecondsToUnix(ctr.CreatedAt),
						Labels:      ctr.Labels,
					},
				},
			}
		} else {
			podSandboxStatus, _ := c.client.PodSandboxStatus(ctx, ctr.GetPodSandboxId(), false)
			if podSandboxStatus == nil {
				podSandboxStatus = &v1.PodSandboxStatusResponse{}
			}
			evts[idx] = event.Event{
				IsCreate: true,
				Info:     c.ctrToInfo(ctx, container.Status, podSandboxStatus.GetStatus(), container.GetInfo(), podSandboxStatus.GetInfo()),
			}
		}
	}
	return evts, nil
}

func (c *criEngine) Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error) {
	containerEventsCh := make(chan *v1.ContainerEventResponse)
	wg.Add(1)
	go func() {
		defer close(containerEventsCh)
		defer wg.Done()
		_ = c.client.GetContainerEvents(ctx, containerEventsCh, nil)
	}()
	outCh := make(chan event.Event)
	wg.Add(1)
	go func() {
		defer close(outCh)
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case evt := <-containerEventsCh:
				if evt == nil {
					// Nothing to do for nil event
					break
				}
				switch evt.ContainerEventType {
				case v1.ContainerEventType_CONTAINER_CREATED_EVENT:
					if !config.IsHookEnabled(config.HookCreate) {
						// Skip
						continue
					}
				case v1.ContainerEventType_CONTAINER_STARTED_EVENT:
					if !config.IsHookEnabled(config.HookStart) {
						// Skip
						continue
					}
				case v1.ContainerEventType_CONTAINER_DELETED_EVENT:
					// Always enabled
				}

				var info event.Info
				// verbose true to return container.Info
				ctr, err := c.client.ContainerStatus(ctx, evt.ContainerId, true)
				if err != nil || ctr == nil {
					info = event.Info{
						Container: event.Container{
							Type:        c.runtime,
							ID:          shortContainerID(evt.ContainerId),
							FullID:      evt.ContainerId,
							CreatedTime: nanoSecondsToUnix(evt.CreatedAt),
						},
					}
				} else {
					cPodSandbox := evt.GetPodSandboxStatus()
					podSandboxStatus, _ := c.client.PodSandboxStatus(ctx, cPodSandbox.GetId(), false)
					if podSandboxStatus == nil {
						podSandboxStatus = &v1.PodSandboxStatusResponse{}
					}
					info = c.ctrToInfo(ctx, ctr.GetStatus(), cPodSandbox, ctr.GetInfo(), podSandboxStatus.GetInfo())
				}
				outCh <- event.Event{
					Info:     info,
					IsCreate: evt.ContainerEventType != v1.ContainerEventType_CONTAINER_DELETED_EVENT,
				}
			}
		}
	}()
	return outCh, nil
}
