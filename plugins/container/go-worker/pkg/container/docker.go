package container

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"strings"
	"sync"
	"time"
)

const k8sLastAppliedConfigLabel = "io.kubernetes.container.last-applied-config"

func init() {
	engineGenerators[typeDocker] = newDockerEngine
}

type dockerEngine struct {
	*client.Client
	socket string
}

func newDockerEngine(_ context.Context, socket string) (Engine, error) {
	cl, err := client.NewClientWithOpts(client.FromEnv,
		client.WithAPIVersionNegotiation(),
		client.WithHost(enforceUnixProtocolIfEmpty(socket)))
	if err != nil {
		return nil, err
	}
	return &dockerEngine{Client: cl, socket: socket}, nil
}

func (dc *dockerEngine) copy(ctx context.Context) (Engine, error) {
	return newDockerEngine(ctx, dc.socket)
}

type Probe struct {
	Exec *struct {
		Command []string `json:"command"`
	} `json:"exec"`
}

type Healthcheck struct {
	Test []string `json:"Test"`
}

type k8sPodSpecInfo struct {
	Spec *struct {
		Containers []struct {
			LivenessProbe  *Probe       `json:"livenessProbe"`
			ReadinessProbe *Probe       `json:"readinessProbe"`
			Healthcheck    *Healthcheck `json:"healthcheck"`
		} `json:"containers"`
	} `json:"spec"`
}

// normalizeArg removes pairs of leading/trailing " or ' chars, if present
func normalizeArg(val string) string {
	strings.TrimPrefix(val, `"`)
	strings.TrimPrefix(val, `'`)
	return val
}

func parseLivenessReadinessProbe(probe *Probe) *event.Probe {
	if probe == nil || probe.Exec == nil || probe.Exec.Command == nil {
		return nil
	}
	p := event.Probe{}
	p.Exe = normalizeArg(probe.Exec.Command[0])
	for _, arg := range probe.Exec.Command[1:] {
		p.Args = append(p.Args, normalizeArg(arg))
	}
	return &p
}

func parseHealthcheckProbe(hcheck *container.HealthConfig) *event.Probe {
	if hcheck == nil || len(hcheck.Test) <= 1 {
		return nil
	}
	p := event.Probe{}

	switch hcheck.Test[0] {
	case "CMD":
		p.Exe = normalizeArg(hcheck.Test[1])
		for _, arg := range hcheck.Test[2:] {
			p.Args = append(p.Args, normalizeArg(arg))
		}
	case "CMD-SHELL":
		p.Exe = "/bin/sh"
		p.Args = append(p.Args, "-c")
		p.Args = append(p.Args, hcheck.Test[1])
	default:
		return nil
	}
	return &p
}

func (dc *dockerEngine) ctrToInfo(ctx context.Context, ctr types.ContainerJSON) event.Info {
	hostCfg := ctr.HostConfig
	if hostCfg == nil {
		hostCfg = &container.HostConfig{
			Resources: container.Resources{
				CPUPeriod: defaultCpuPeriod,
				CPUShares: defaultCpuShares,
			},
		}
	}
	mounts := make([]event.Mount, 0)
	for _, m := range ctr.Mounts {
		mounts = append(mounts, event.Mount{
			Source:      m.Source,
			Destination: m.Destination,
			Mode:        m.Mode,
			RW:          m.RW,
			Propagation: string(m.Propagation),
		})
	}

	var name string
	isPodSandbox := false
	name = strings.TrimPrefix(ctr.Name, "/")
	isPodSandbox = strings.Contains(name, "k8s_POD")

	netCfg := ctr.NetworkSettings
	if netCfg == nil {
		netCfg = &types.NetworkSettings{}
	}
	portMappings := make([]event.PortMapping, 0)
	for port, portBindings := range netCfg.Ports {
		if port.Proto() != "tcp" {
			continue
		}
		containerPort := port.Int()
		for _, portBinding := range portBindings {
			hostIP, err := parsePortBindingHostIP(portBinding.HostIP)
			if err != nil {
				continue
			}

			hostPort, err := parsePortBindingHostPort(portBinding.HostPort)
			if err != nil {
				continue
			}

			portMappings = append(portMappings, event.PortMapping{
				HostIP:        hostIP,
				HostPort:      hostPort,
				ContainerPort: containerPort,
			})
		}
	}
	cfg := ctr.Config
	if cfg == nil {
		cfg = &container.Config{}
	}

	image, _, err := dc.ImageInspectWithRaw(ctx, ctr.Image)
	if err != nil {
		image = types.ImageInspect{}
	}

	var (
		imageDigest string
		imageRepo   string
		imageTag    string
		imageID     string
	)
	imageDigestSet := make([]string, 0)
	for _, repoDigest := range image.RepoDigests {
		repoDigestParts := strings.Split(repoDigest, "@")
		if len(repoDigestParts) != 2 {
			// malformed
			continue
		}
		if imageRepo == "" {
			imageRepo = repoDigestParts[0]
		}
		digest := repoDigestParts[1]
		imageDigestSet = append(imageDigestSet, digest)
		if strings.Contains(repoDigest, imageRepo) {
			imageDigest = digest
			break
		}
	}
	if len(imageDigest) == 0 && len(imageDigestSet) == 1 {
		imageDigest = imageDigestSet[0]
	}

	for _, repoTag := range image.RepoTags {
		repoTagsParts := strings.Split(repoTag, ":")
		if len(repoTagsParts) != 2 {
			// malformed
			continue
		}
		if imageRepo == "" {
			imageRepo = repoTagsParts[0]
		}
		if strings.Contains(repoTag, imageRepo) {
			imageTag = repoTagsParts[1]
			break
		}
	}

	img := ctr.Image
	if !strings.Contains(img, "/") && strings.Contains(img, ":") {
		imageID = strings.Split(img, ":")[1]
	}

	labels := make(map[string]string)
	var (
		livenessProbe    *event.Probe = nil
		readinessProbe   *event.Probe = nil
		healthcheckProbe *event.Probe = nil
	)
	for key, val := range cfg.Labels {
		if len(val) <= config.GetLabelMaxLen() {
			labels[key] = val
		}
		if key == k8sLastAppliedConfigLabel {
			var k8sPodInfo k8sPodSpecInfo
			err = json.Unmarshal([]byte(val), &k8sPodInfo)
			if err == nil {
				if k8sPodInfo.Spec.Containers[0].LivenessProbe != nil {
					livenessProbe = parseLivenessReadinessProbe(k8sPodInfo.Spec.Containers[0].LivenessProbe)
				} else if k8sPodInfo.Spec.Containers[0].ReadinessProbe != nil {
					readinessProbe = parseLivenessReadinessProbe(k8sPodInfo.Spec.Containers[0].ReadinessProbe)
				}
			}
		}
	}
	if livenessProbe == nil && readinessProbe == nil && cfg.Healthcheck != nil {
		healthcheckProbe = parseHealthcheckProbe(cfg.Healthcheck)
	}

	ip := netCfg.IPAddress
	if ip == "" {
		if hostCfg.NetworkMode.IsContainer() {
			secondaryID := hostCfg.NetworkMode.ConnectedContainer()
			secondary, _ := dc.ContainerInspect(ctx, secondaryID)
			if secondary.NetworkSettings != nil {
				ip = secondary.NetworkSettings.IPAddress
			}
		}
	}

	createdTime, _ := time.Parse(time.RFC3339Nano, ctr.Created)

	var (
		cpuShares int64 = defaultCpuShares
		cpuPeriod int64 = defaultCpuPeriod
	)
	if hostCfg.CPUShares > 0 {
		cpuShares = hostCfg.CPUShares
	}
	if hostCfg.CPUPeriod > 0 {
		cpuPeriod = hostCfg.CPUPeriod
	}
	cpusetCount := countCPUSet(hostCfg.CpusetCpus)

	var size int64 = -1
	if ctr.SizeRw != nil {
		size = *ctr.SizeRw
	}

	return event.Info{
		Container: event.Container{
			Type:             typeDocker.ToCTValue(),
			ID:               shortContainerID(ctr.ID),
			Name:             name,
			Image:            cfg.Image,
			ImageDigest:      imageDigest,
			ImageID:          imageID,
			ImageRepo:        imageRepo,
			ImageTag:         imageTag,
			User:             cfg.User,
			CPUPeriod:        cpuPeriod,
			CPUQuota:         hostCfg.CPUQuota,
			CPUShares:        cpuShares,
			CPUSetCPUCount:   cpusetCount,
			CreatedTime:      createdTime.Unix(),
			Env:              cfg.Env,
			FullID:           ctr.ID,
			HostIPC:          hostCfg.IpcMode.IsHost(),
			HostNetwork:      hostCfg.NetworkMode.IsHost(),
			HostPID:          hostCfg.PidMode.IsHost(),
			Ip:               ip,
			IsPodSandbox:     isPodSandbox,
			Labels:           labels,
			MemoryLimit:      hostCfg.Memory,
			SwapLimit:        hostCfg.MemorySwap,
			Privileged:       hostCfg.Privileged,
			PortMappings:     portMappings,
			Mounts:           mounts,
			Size:             size,
			LivenessProbe:    livenessProbe,
			ReadinessProbe:   readinessProbe,
			HealthcheckProbe: healthcheckProbe,
		},
	}
}

func (dc *dockerEngine) get(ctx context.Context, containerId string) (*event.Event, error) {
	ctrJson, _, err := dc.ContainerInspectWithRaw(ctx, containerId, config.GetWithSize())
	if err != nil {
		return nil, err
	}

	return &event.Event{
		Info:     dc.ctrToInfo(ctx, ctrJson),
		IsCreate: true,
	}, nil
}

func (dc *dockerEngine) Name() string {
	return string(typeDocker)
}

func (dc *dockerEngine) Sock() string {
	return dc.socket
}

func (dc *dockerEngine) List(ctx context.Context) ([]event.Event, error) {
	containers, err := dc.ContainerList(ctx, container.ListOptions{All: true})
	if err != nil {
		return nil, err
	}

	evts := make([]event.Event, len(containers))
	for idx, ctr := range containers {
		ctrJson, _, err := dc.ContainerInspectWithRaw(ctx, ctr.ID, config.GetWithSize())
		if err != nil {
			// Minimum set of infos
			evts[idx] = event.Event{
				Info: event.Info{
					Container: event.Container{
						Type:        typeDocker.ToCTValue(),
						ID:          shortContainerID(ctr.ID),
						Image:       ctr.Image,
						FullID:      ctr.ID,
						ImageID:     ctr.ImageID,
						CreatedTime: nanoSecondsToUnix(ctr.Created),
					},
				},
				IsCreate: true,
			}
		}
		evts[idx] = event.Event{
			Info:     dc.ctrToInfo(ctx, ctrJson),
			IsCreate: true,
		}
	}
	return evts, nil
}

func (dc *dockerEngine) Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error) {
	outCh := make(chan event.Event)

	flts := filters.NewArgs()
	flts.Add("type", string(events.ContainerEventType))
	if config.IsHookEnabled(config.HookCreate) {
		flts.Add("event", string(events.ActionCreate))
	}
	if config.IsHookEnabled(config.HookStart) {
		flts.Add("event", string(events.ActionStart))
	}
	flts.Add("event", string(events.ActionDestroy))

	msgs, _ := dc.Events(ctx, events.ListOptions{Filters: flts})
	wg.Add(1)
	go func() {
		defer close(outCh)
		defer wg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-msgs:
				var (
					ctrJson types.ContainerJSON
					err     error
				)
				switch msg.Action {
				case events.ActionCreate, events.ActionStart:
					ctrJson, _, err = dc.ContainerInspectWithRaw(ctx, msg.Actor.ID, config.GetWithSize())
					if err == nil {
						outCh <- event.Event{
							Info:     dc.ctrToInfo(ctx, ctrJson),
							IsCreate: true,
						}
					}
				case events.ActionDestroy:
					err = errors.New("inspect useless on action destroy")
				}

				// This is called for ActionDestroy
				// AND as a fallback whenever ContainerInspectWithRaw fails.
				if err != nil {
					// At least send an event with the minimum set of data
					outCh <- event.Event{
						Info: event.Info{
							Container: event.Container{
								Type:   typeDocker.ToCTValue(),
								ID:     shortContainerID(msg.Actor.ID),
								FullID: msg.Actor.ID,
								Image:  msg.Actor.Attributes["image"],
							},
						},
						IsCreate: msg.Action != events.ActionDestroy,
					}
				}
			}
		}
	}()
	return outCh, nil
}
