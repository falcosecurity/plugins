//go:build linux

package container

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"

	"github.com/moby/moby/api/types/events"
	"go.podman.io/podman/v6/libpod/define"
	"go.podman.io/podman/v6/pkg/bindings"
	"go.podman.io/podman/v6/pkg/bindings/containers"
	"go.podman.io/podman/v6/pkg/bindings/system"
	"go.podman.io/podman/v6/pkg/domain/entities/types"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

func init() {
	engineGenerators[typePodman] = newPodmanEngine
}

type podmanEngine struct {
	pCtx   context.Context
	socket string
}

func newPodmanEngine(ctx context.Context, _ *slog.Logger, socket string) (Engine, error) {
	// bindings.NewConnection pings the service and returns a context that
	// carries the connection; every later request derives from it, so a
	// deadline on ctx itself would expire the whole engine. Bound the ping
	// only: cancel the connection context if the engine timeout elapses first,
	// then detach it once the service has answered.
	connCtx, cancelConn := context.WithCancelCause(ctx)
	pingCtx, cancelPing := WithEngineTimeout(ctx)
	defer cancelPing()
	stop := context.AfterFunc(pingCtx, func() {
		cancelConn(context.Cause(pingCtx))
	})
	conn, err := bindings.NewConnection(connCtx, enforceUnixProtocolIfEmpty(socket))
	if !stop() && err == nil {
		// The timeout fired while the service was answering: the connection
		// context is cancelled and the engine would never work.
		err = context.Cause(pingCtx)
	}
	if err != nil {
		cancelConn(err)
		return nil, err
	}
	return &podmanEngine{pCtx: conn, socket: socket}, nil
}

func (pc *podmanEngine) copy(ctx context.Context) (Engine, error) {
	// TODO: change to use logger member once handled
	return newPodmanEngine(ctx, nil, pc.socket)
}

// requestCtx derives a request context from the connection context, which is
// what carries the podman client, and ties it to the caller's context so that
// the deadline and cancellation set by the caller are honoured.
func (pc *podmanEngine) requestCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	reqCtx, cancel := context.WithCancelCause(pc.pCtx)
	stop := context.AfterFunc(ctx, func() {
		cancel(context.Cause(ctx))
	})
	return reqCtx, func() {
		stop()
		cancel(nil)
	}
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
	imageRepo, imageTag = parseImageRepoTag(ctr.ImageName)

	labels := make(map[string]string)
	for key, val := range cfg.Labels {
		if len(val) <= config.GetLabelMaxLen() {
			labels[key] = val
		}
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
		},
	}
}

func (pc *podmanEngine) get(ctx context.Context, containerId string) (*event.Event, error) {
	ctx, cancel := pc.requestCtx(ctx)
	defer cancel()
	size := config.GetWithSize()
	ctrInfo, err := containers.Inspect(ctx, containerId, &containers.InspectOptions{Size: &size})
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

func (pc *podmanEngine) List(ctx context.Context) ([]event.Event, error) {
	ctx, cancel := pc.requestCtx(ctx)
	defer cancel()
	evts := make([]event.Event, 0)
	all := true
	size := config.GetWithSize()
	cList, err := containers.List(ctx, &containers.ListOptions{All: &all})
	if err != nil {
		return nil, err
	}
	// incomplete reports the containers from index from on as not inspected.
	incomplete := func(from int, cut error) *ListIncompleteError {
		return &ListIncompleteError{NotInspected: notInspectedFrom(len(cList), from, func(i int) string { return cList[i].ID }), Err: cut}
	}
	for idx, c := range cList {
		// Once the caller's context is done every request fails, but only
		// after the three attempts and the fixed pauses of the podman client:
		// stop here rather than paying them for each remaining container, and
		// leave those containers to the background lookups instead of
		// returning them with partial metadata.
		if cut := listCut(ctx); cut != nil {
			return evts, incomplete(idx, cut)
		}
		ctrInfo, err := containers.Inspect(ctx, c.ID, &containers.InspectOptions{Size: &size})
		if cut := listCut(ctx); cut != nil {
			return evts, incomplete(idx, cut)
		}
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
	if config.IsHookEnabled(config.HookRemove) {
		filters["event"] = append(filters["event"], string(events.ActionRemove))
	}

	evChn := make(chan types.Event)
	cancelChan := make(chan bool)
	err := system.Events(pc.pCtx, evChn, cancelChan, &system.EventsOptions{
		Filters: filters,
		Stream:  &stream,
	})
	if err != nil {
		return nil, err
	}

	outCh := make(chan event.Event)
	wg.Add(1)
	go func() {
		defer func() {
			wg.Done()
			close(cancelChan)
			close(outCh)
		}()
		size := config.GetWithSize()
		// Blocking: convert all events from podman to json strings
		// and send them to the main loop until the channel is closed
		for {
			select {
			case <-ctx.Done():
				cancelChan <- true
				return
			case ev, ok := <-evChn:
				if !ok {
					// evChn has been closed - kill the goroutine
					// NOTE this should never happen since we are the ones closing the channel.
					return
				}
				var (
					ctr *define.InspectContainerData
					err error
				)
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
