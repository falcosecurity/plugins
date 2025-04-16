package container

import (
	"context"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	shortIDLength = 12
	// Default values from
	//https://github.com/falcosecurity/libs/blob/39c0e0dcb9d1d23e46b13f4963a9a7106db1f650/userspace/libsinsp/container_info.h#L218
	defaultCpuPeriod = 100000
	defaultCpuShares = 1024

	typeDocker     engineType = "docker"
	typePodman     engineType = "podman"
	typeCri        engineType = "cri"
	typeCrio       engineType = "cri-o"
	typeContainerd engineType = "containerd"
)

type engineType string

// ToCTValue returns integer representation: CT_DOCKER,CT_PODMAN etc etc
// See src/container_type.h
func (t engineType) ToCTValue() int {
	switch t {
	case typeDocker:
		return 0
	case typePodman:
		return 11
	case typeCri:
		return 6
	case typeContainerd:
		return 7
	case typeCrio:
		return 8
	default:
		return 0xffff // unknown
	}
}

type engineGenerator func(context.Context, string) (Engine, error)
type EngineGenerator func(ctx context.Context) (Engine, error)

// Hooked up by each engine through init()
var engineGenerators = make(map[engineType]engineGenerator)

func Generators() ([]EngineGenerator, error) {
	generators := make([]EngineGenerator, 0)

	c := config.Get()
	for engineName, engineGen := range engineGenerators {
		eCfg, ok := c.SocketsEngines[string(engineName)]
		if !ok || !eCfg.Enabled {
			continue
		}
		// For each specified socket, return a closure to generate its engine
		for _, socket := range eCfg.Sockets {
			// Properly account for HOST_ROOT env variable
			socket = filepath.Join(config.GetHostRoot(), socket)
			// Even if `stat` returns an err that is not NotExist,
			// try to generate an engine for the socket.
			if _, statErr := os.Stat(socket); !os.IsNotExist(statErr) {
				generators = append(generators, func(ctx context.Context) (Engine, error) {
					return engineGen(ctx, socket)
				})
			}
		}
	}
	return generators, nil
}

type getter interface {
	// get returns info about a single container
	get(ctx context.Context, containerId string) (*event.Event, error)
}

type copier interface {
	// copy creates a new Engine with same socket of another.
	copy(ctx context.Context) (Engine, error)
}

type Engine interface {
	Name() string
	Sock() string
	// List lists all running container for the engine
	List(ctx context.Context) ([]event.Event, error)
	// Listen returns a channel where container created/deleted events will be notified
	Listen(ctx context.Context, wg *sync.WaitGroup) (<-chan event.Event, error)
}

func enforceUnixProtocolIfEmpty(socket string) string {
	base, _ := url.Parse(socket)
	if base.Scheme == "" {
		base.Scheme = "unix"
		return base.String()
	}
	return socket
}

func nanoSecondsToUnix(ns int64) int64 {
	return time.Unix(0, ns).Unix()
}

// Examples:
// 1,7 -> 2
// 1-4,7 -> 4 + 1 -> 5
// 1-4,7-10,12 -> 4 + 4 + 1 -> 9
func countCPUSet(cpuSet string) int64 {
	var counter int64
	if cpuSet == "" {
		return counter
	}
	cpusetParts := strings.Split(cpuSet, ",")
	for _, cpusetPart := range cpusetParts {
		cpuSetDash := strings.Split(cpusetPart, "-")
		if len(cpuSetDash) > 1 {
			if len(cpuSetDash) > 2 {
				// malformed
				return 0
			}
			start, err := strconv.ParseInt(cpuSetDash[0], 10, 64)
			if err != nil {
				return 0
			}
			end, err := strconv.ParseInt(cpuSetDash[1], 10, 64)
			if err != nil {
				return 0
			}
			counter += end - start + 1
		} else {
			counter++
		}
	}
	return counter
}

func shortContainerID(id string) string {
	if len(id) > shortIDLength {
		return id[:shortIDLength]
	}
	return id
}
