package container

import (
	"encoding/json"
	"strings"

	"github.com/docker/docker/api/types/container"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

const k8sLastAppliedConfigLabel = "io.kubernetes.container.last-applied-config"

const k8sLastAppliedConfigAnnotation = "kubectl.kubernetes.io/last-applied-configuration"

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
			Name           string       `json:"name"`
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

// parseProbesFromPodAnnotation parses the full pod spec JSON from the
// kubectl.kubernetes.io/last-applied-configuration pod-level annotation,
// finds the container matching containerName, and extracts its liveness/readiness probes.
func parseProbesFromPodAnnotation(annotation string, containerName string) (liveness *event.Probe, readiness *event.Probe) {
	var k8sPodInfo k8sPodSpecInfo
	if err := json.Unmarshal([]byte(annotation), &k8sPodInfo); err != nil {
		return nil, nil
	}
	if k8sPodInfo.Spec == nil {
		return nil, nil
	}
	for _, c := range k8sPodInfo.Spec.Containers {
		if c.Name == containerName {
			if c.LivenessProbe != nil {
				liveness = parseLivenessReadinessProbe(c.LivenessProbe)
			}
			if c.ReadinessProbe != nil {
				readiness = parseLivenessReadinessProbe(c.ReadinessProbe)
			}
			return liveness, readiness
		}
	}
	return nil, nil
}
