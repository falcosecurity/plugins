//go:build linux

package container

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/containers/podman/v5/libpod/define"
	"github.com/containers/podman/v5/pkg/bindings"
	"github.com/containers/podman/v5/pkg/bindings/containers"
	"github.com/containers/podman/v5/pkg/bindings/system"
	"github.com/containers/podman/v5/pkg/domain/entities/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"strconv"
	"strings"
	"sync"
	"time"
)

func init() {
	engineGenerators[typePodman] = newPodmanEngine
}

type podmanEngine struct {
	pCtx   context.Context
	socket string
}

func newPodmanEngine(ctx context.Context, socket string) (Engine, error) {
	conn, err := bindings.NewConnection(ctx, enforceUnixProtocolIfEmpty(socket))
	if err != nil {
		return nil, err
	}
	return &podmanEngine{pCtx: conn, socket: socket}, nil
}

func (pc *podmanEngine) copy(ctx context.Context) (Engine, error) {
	return newPodmanEngine(ctx, pc.socket)
}

func (pc *podmanEngine) ctrToInfo(ctr *define.InspectContainerData) event.Info {
	cfg := ctr.Config
	if cfg == nil {
		cfg = &define.InspectContainerConfig{}
	}
	hostCfg := ctr.HostConfig
	if hostCfg == nil {
		hostCfg = &define.InspectContainerHostConfig{}
	}
	netCfg := ctr.NetworkSettings
	if netCfg == nil {
		netCfg = &define.InspectNetworkSettings{}
	}
	var name string
	isPodSandbox := false
	name = strings.TrimPrefix(ctr.Name, "/")
	isPodSandbox = strings.Contains(name, "k8s_POD")

	mounts := make([]event.Mount, 0)
	for _, m := range ctr.Mounts {
		mounts = append(mounts, event.Mount{
			Source:      m.Source,
			Destination: m.Destination,
			Mode:        m.Mode,
			RW:          m.RW,
			Propagation: m.Propagation,
		})
	}

	portMappings := make([]event.PortMapping, 0)
	for port, portBindings := range netCfg.Ports {
		if !strings.Contains(port, "/tcp") {
			continue
		}
		containerPort, err := strconv.Atoi(port)
		if err != nil {
			continue
		}
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

	var (
		imageRepo string
		imageTag  string
	)
	imageRepoTag := strings.Split(ctr.ImageName, ":")
	if len(imageRepoTag) == 2 {
		imageRepo = imageRepoTag[0]
		imageTag = imageRepoTag[1]
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
			err := json.Unmarshal([]byte(val), &k8sPodInfo)
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
		hConfig := container.HealthConfig{
			Test:          cfg.Healthcheck.Test,
			Interval:      cfg.Healthcheck.Interval,
			Timeout:       cfg.Healthcheck.Timeout,
			StartPeriod:   cfg.Healthcheck.StartPeriod,
			StartInterval: cfg.Healthcheck.StartInterval,
			Retries:       cfg.Healthcheck.Retries,
		}
		healthcheckProbe = parseHealthcheckProbe(&hConfig)
	}

	var (
		cpuShares int64 = defaultCpuShares
		cpuPeriod int64 = defaultCpuPeriod
	)
	if hostCfg.CpuShares > 0 {
		cpuShares = int64(hostCfg.CpuShares)
	}
	if hostCfg.CpuPeriod > 0 {
		cpuPeriod = int64(hostCfg.CpuPeriod)
	}
	cpusetCount := countCPUSet(hostCfg.CpusetCpus)

	var size int64 = -1
	if ctr.SizeRw != nil {
		size = *ctr.SizeRw
	}

	return event.Info{
		Container: event.Container{
			Type:             typePodman.ToCTValue(),
			ID:               shortContainerID(ctr.ID),
			Name:             name,
			Image:            ctr.ImageName,
			ImageDigest:      ctr.ImageDigest,
			ImageID:          ctr.Image,
			ImageRepo:        imageRepo,
			ImageTag:         imageTag,
			User:             cfg.User,
			CPUPeriod:        cpuPeriod,
			CPUQuota:         hostCfg.CpuQuota,
			CPUShares:        cpuShares,
			CPUSetCPUCount:   cpusetCount,
			CreatedTime:      ctr.Created.Unix(),
			Env:              cfg.Env,
			FullID:           ctr.ID,
			HostIPC:          hostCfg.IpcMode == "host",
			HostNetwork:      hostCfg.NetworkMode == "host",
			HostPID:          hostCfg.PidMode == "host",
			Ip:               netCfg.IPAddress,
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

func (pc *podmanEngine) get(_ context.Context, containerId string) (*event.Event, error) {
	size := config.GetWithSize()
	ctrInfo, err := containers.Inspect(pc.pCtx, containerId, &containers.InspectOptions{Size: &size})
	if err != nil {
		return nil, err
	}

	return &event.Event{
		Info:     pc.ctrToInfo(ctrInfo),
		IsCreate: true,
	}, nil
}

func (pc *podmanEngine) Name() string {
	return string(typePodman)
}

func (pc *podmanEngine) Sock() string {
	return pc.socket
}

func (pc *podmanEngine) List(_ context.Context) ([]event.Event, error) {
	evts := make([]event.Event, 0)
	all := true
	size := config.GetWithSize()
	cList, err := containers.List(pc.pCtx, &containers.ListOptions{All: &all})
	if err != nil {
		return nil, err
	}
	for _, c := range cList {
		ctrInfo, err := containers.Inspect(pc.pCtx, c.ID, &containers.InspectOptions{Size: &size})
		if err != nil {
			evts = append(evts, event.Event{
				Info: event.Info{
					Container: event.Container{
						Type:        typePodman.ToCTValue(),
						ID:          shortContainerID(c.ID),
						Image:       c.Image,
						FullID:      c.ID,
						ImageID:     c.ImageID,
						CreatedTime: c.Created.Unix(),
					},
				},
				IsCreate: true,
			})
		} else {
			evts = append(evts, event.Event{
				Info:     pc.ctrToInfo(ctrInfo),
				IsCreate: true,
			})
		}

	}
	return evts, nil
}

// Set up container created event listener by call to system.Events
// In case events have been disabled in the podmanEngine an error will be captured and passed to the caller
func (pc *podmanEngine) Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error) {
	stream := true

	filters := map[string][]string{
		"type":  {string(events.ContainerEventType)},
		"event": make([]string, 0),
	}
	if config.IsHookEnabled(config.HookCreate) {
		filters["event"] = append(filters["event"], string(events.ActionCreate))
	}
	if config.IsHookEnabled(config.HookStart) {
		filters["event"] = append(filters["event"], string(events.ActionStart))
	}
	filters["event"] = append(filters["event"], string(events.ActionRemove))

	evChn := make(chan types.Event)
	evErrorChn := make(chan error)
	const eventsErrorTimeout = 10 * time.Millisecond
	cancelChan := make(chan bool)
	wg.Add(1)
	// producers
	go func(ch chan types.Event) {
		defer wg.Done()
		evErrorChn <- system.Events(pc.pCtx, ch, cancelChan, &system.EventsOptions{
			Filters: filters,
			Stream:  &stream,
		})
	}(evChn)

	// Catch error on initialization of evChn
	select {
	case err := <-evErrorChn:
		return nil, err
	case <-time.After(eventsErrorTimeout):
		// continue reading of error channel to avoid blocking initial go-routine
		go func() {
			for {
				if _, ok := <-evErrorChn; !ok {
					break
				}
			}
		}()
	}

	outCh := make(chan event.Event)
	wg.Add(1)
	go func() {
		defer close(outCh)
		defer close(cancelChan)
		defer wg.Done()
		size := config.GetWithSize()
		// Blocking: convert all events from podman to json strings
		// and send them to the main loop until the channel is closed
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-evChn:
				var (
					ctr *define.InspectContainerData
					err error
				)
				if !ok {
					// evChn has been closed - block further reads from channel
					evChn = nil
				}
				switch ev.Action {
				case events.ActionCreate, events.ActionStart:
					ctr, err = containers.Inspect(pc.pCtx, ev.Actor.ID, &containers.InspectOptions{Size: &size})
					if err == nil {
						outCh <- event.Event{
							Info:     pc.ctrToInfo(ctr),
							IsCreate: true,
						}
					}
				case events.ActionRemove:
					err = errors.New("inspect useless on action destroy")
				}

				// This is called for ActionRemove
				// AND as a fallback whenever Inspect fails.
				if err != nil {
					// At least send an event with the minimal set of data
					outCh <- event.Event{
						Info: event.Info{
							Container: event.Container{
								Type:   typePodman.ToCTValue(),
								ID:     shortContainerID(ev.Actor.ID),
								FullID: ev.Actor.ID,
								Image:  ev.Actor.Attributes["image"],
							},
						},
						IsCreate: ev.Action != events.ActionRemove,
					}
				}
			}
		}
	}()
	return outCh, nil
}
