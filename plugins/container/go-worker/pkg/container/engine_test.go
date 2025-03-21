package container

import (
	"github.com/docker/docker/client"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEnforceUnixProtocol(t *testing.T) {
	tCases := map[string]struct {
		socket         string
		expectedSocket string
	}{
		"With specified protocol": {
			socket:         client.DefaultDockerHost,
			expectedSocket: client.DefaultDockerHost,
		},
		"Without specified protocol": {
			socket:         "/var/run/docker.sock",
			expectedSocket: client.DefaultDockerHost,
		},
	}

	for name, tc := range tCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expectedSocket, enforceUnixProtocolIfEmpty(tc.socket))
		})
	}
}

func TestCountCPUSet(t *testing.T) {
	tCases := map[string]struct {
		cpuSetStr           string
		expectedCpuSetCount int64
	}{
		"None": {
			cpuSetStr:           "",
			expectedCpuSetCount: 0,
		},
		"With single cpu": {
			cpuSetStr:           "3",
			expectedCpuSetCount: 1,
		},
		"With multiple cpus": {
			cpuSetStr:           "1,2,6",
			expectedCpuSetCount: 3,
		},
		"With single interval": {
			cpuSetStr:           "1-3",
			expectedCpuSetCount: 3,
		},
		"With multiple intervals": {
			cpuSetStr:           "1-3,6-8",
			expectedCpuSetCount: 6,
		},
		"With mixed intervals and cpus": {
			cpuSetStr:           "1-3,6-8,12,16",
			expectedCpuSetCount: 8,
		},
	}

	for name, tc := range tCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expectedCpuSetCount, countCPUSet(tc.cpuSetStr))
		})
	}
}
