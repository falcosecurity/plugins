package container

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/falcosecurity/plugins/plugins/container/go-worker/pkg/event"
)

func TestParseProbesFromPodAnnotation(t *testing.T) {
	tests := []struct {
		name              string
		annotation        string
		containerName     string
		expectedLiveness  *event.Probe
		expectedReadiness *event.Probe
	}{
		{
			name: "single container with liveness probe",
			annotation: `{
				"spec": {
					"containers": [{
						"name": "myapp",
						"livenessProbe": {
							"exec": {
								"command": ["/bin/healthcheck", "--live"]
							}
						}
					}]
				}
			}`,
			containerName: "myapp",
			expectedLiveness: &event.Probe{
				Exe:  "/bin/healthcheck",
				Args: []string{"--live"},
			},
			expectedReadiness: nil,
		},
		{
			name: "single container with readiness probe",
			annotation: `{
				"spec": {
					"containers": [{
						"name": "myapp",
						"readinessProbe": {
							"exec": {
								"command": ["/bin/healthcheck", "--ready"]
							}
						}
					}]
				}
			}`,
			containerName: "myapp",
			expectedLiveness: nil,
			expectedReadiness: &event.Probe{
				Exe:  "/bin/healthcheck",
				Args: []string{"--ready"},
			},
		},
		{
			name: "single container with both probes",
			annotation: `{
				"spec": {
					"containers": [{
						"name": "myapp",
						"livenessProbe": {
							"exec": {
								"command": ["/bin/healthcheck", "--live"]
							}
						},
						"readinessProbe": {
							"exec": {
								"command": ["/bin/healthcheck", "--ready"]
							}
						}
					}]
				}
			}`,
			containerName: "myapp",
			expectedLiveness: &event.Probe{
				Exe:  "/bin/healthcheck",
				Args: []string{"--live"},
			},
			expectedReadiness: &event.Probe{
				Exe:  "/bin/healthcheck",
				Args: []string{"--ready"},
			},
		},
		{
			name: "multi-container pod matches correct container",
			annotation: `{
				"spec": {
					"containers": [
						{
							"name": "sidecar",
							"livenessProbe": {
								"exec": {
									"command": ["/sidecar-check"]
								}
							}
						},
						{
							"name": "main",
							"livenessProbe": {
								"exec": {
									"command": ["/main-check", "--verbose"]
								}
							}
						}
					]
				}
			}`,
			containerName: "main",
			expectedLiveness: &event.Probe{
				Exe:  "/main-check",
				Args: []string{"--verbose"},
			},
			expectedReadiness: nil,
		},
		{
			name:              "container name not found in spec",
			annotation:        `{"spec": {"containers": [{"name": "other"}]}}`,
			containerName:     "myapp",
			expectedLiveness:  nil,
			expectedReadiness: nil,
		},
		{
			name:              "malformed JSON",
			annotation:        `{not valid json`,
			containerName:     "myapp",
			expectedLiveness:  nil,
			expectedReadiness: nil,
		},
		{
			name:              "empty annotation",
			annotation:        "",
			containerName:     "myapp",
			expectedLiveness:  nil,
			expectedReadiness: nil,
		},
		{
			name:              "missing spec field",
			annotation:        `{"metadata": {"name": "mypod"}}`,
			containerName:     "myapp",
			expectedLiveness:  nil,
			expectedReadiness: nil,
		},
		{
			name: "container with no probes",
			annotation: `{
				"spec": {
					"containers": [{
						"name": "myapp"
					}]
				}
			}`,
			containerName:     "myapp",
			expectedLiveness:  nil,
			expectedReadiness: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			liveness, readiness := parseProbesFromPodAnnotation(tt.annotation, tt.containerName)
			assert.Equal(t, tt.expectedLiveness, liveness)
			assert.Equal(t, tt.expectedReadiness, readiness)
		})
	}
}
