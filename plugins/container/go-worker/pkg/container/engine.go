package container

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/config"
	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
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

type engineGenerator func(context.Context, *slog.Logger, string) (Engine, error)
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
					return engineGen(ctx, slog.With("engine", engineName), socket)
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

// parsePortBindingHostIP parses the provided address string and returns a numerical representation of it.
// TODO(ekoops): add IPv6 addresses support.
func parsePortBindingHostIP(hostIP string) (uint32, error) {
	addr, err := netip.ParseAddr(hostIP)
	if err != nil {
		return 0, err
	}

	if addr.Is6() {
		// TODO(ekoops): handle IPv6 addresses.
		return 0, fmt.Errorf("ipv6 addresses are not supported")
	}

	ipv4Addr := addr.As4()
	return binary.BigEndian.Uint32(ipv4Addr[:]), nil
}

// parsePortBindingHostPort parses the provided port string and returns a numerical representation of it.
func parsePortBindingHostPort(port string) (uint16, error) {
	convertedPort, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, err
	}

	return uint16(convertedPort), nil
}

// parseImageRepoTag parses a container image string and returns the repository and tag.
// It correctly handles registry URLs with port numbers by only splitting on the last colon
// that appears after the last slash. If the reference includes a digest (via "@"), the
// digest portion is removed first, and then the tag is extracted from the remaining string.
//
// Examples:
//   - "registry.example.com:5000/foo/bar:latest@sha256:digest" -> ("registry.example.com:5000/foo/bar", "latest")
//   - "registry.example.com:5000/foo/bar@sha256:digest" -> ("registry.example.com:5000/foo/bar", "")
//   - "registry.example.com:5000/foo/bar:latest" -> ("registry.example.com:5000/foo/bar", "latest")
//   - "registry.example.com:5000/foo/bar" -> ("registry.example.com:5000/foo/bar", "")
//   - "foo/bar:latest" -> ("foo/bar", "latest")
//   - "foo:latest" -> ("foo", "latest")
func parseImageRepoTag(image string) (repo, tag string) {
	if image == "" {
		return "", ""
	}

	// Remove digest portion (e.g., @sha256:...) if present
	if at := strings.Index(image, "@"); at != -1 {
		image = image[:at]
	}

	// Find the last slash to separate the registry/path from the image name
	lastSlash := strings.LastIndex(image, "/")

	// Find the last colon after the last slash (if any)
	// This colon separates the tag from the repo
	lastColon := strings.LastIndex(image, ":")

	// If there's no colon, or the colon appears before the last slash
	// (meaning it's part of a registry port), then there's no tag
	if lastColon == -1 || (lastSlash != -1 && lastColon < lastSlash) {
		return image, ""
	}

	return image[:lastColon], image[lastColon+1:]
}
