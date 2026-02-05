package container

import (
	"encoding/binary"
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

func TestParsePortBindingHostIP(t *testing.T) {
	tCases := map[string]struct {
		hostIP          string
		parsedHostIP    uint32
		successExpected bool
	}{
		"127.0.0.1": {
			hostIP:          "127.0.0.1",
			parsedHostIP:    binary.BigEndian.Uint32([]byte{127, 0, 0, 1}),
			successExpected: true,
		},
		"Wrong literal": {
			hostIP:          "Wrong literal",
			parsedHostIP:    0,
			successExpected: false,
		},
		"IPv6 address": {
			hostIP:          "fe80::1",
			parsedHostIP:    0,
			successExpected: false,
		},
	}

	for name, tc := range tCases {
		t.Run(name, func(t *testing.T) {
			if !tc.successExpected {
				_, err := parsePortBindingHostIP(tc.hostIP)
				assert.Error(t, err)
			} else {
				parsedHostIP, err := parsePortBindingHostIP(tc.hostIP)
				assert.NoError(t, err)
				assert.Equal(t, tc.parsedHostIP, parsedHostIP)
			}
		})
	}
}

func TestParsePortBindingHostPort(t *testing.T) {
	tCases := map[string]struct {
		hostPort        string
		parsedHostPort  uint16
		successExpected bool
	}{
		"1000": {
			hostPort:        "1000",
			parsedHostPort:  1000,
			successExpected: true,
		},
		"Wrong literal": {
			hostPort:        "Wrong literal",
			parsedHostPort:  0,
			successExpected: false,
		},
		"Out of range port": {
			hostPort:        "65536",
			parsedHostPort:  0,
			successExpected: false,
		},
	}

	for name, tc := range tCases {
		t.Run(name, func(t *testing.T) {
			if !tc.successExpected {
				_, err := parsePortBindingHostPort(tc.hostPort)
				assert.Error(t, err)
			} else {
				parsedHostPort, err := parsePortBindingHostPort(tc.hostPort)
				assert.NoError(t, err)
				assert.Equal(t, tc.parsedHostPort, parsedHostPort)
			}
		})
	}
}

func TestParseImageRepoTag(t *testing.T) {
	tCases := map[string]struct {
		image        string
		expectedRepo string
		expectedTag  string
	}{
		"Registry with port and tag": {
			image:        "registry.example.com:5000/foo/bar:latest",
			expectedRepo: "registry.example.com:5000/foo/bar",
			expectedTag:  "latest",
		},
		"Registry with port without tag": {
			image:        "registry.example.com:5000/foo/bar",
			expectedRepo: "registry.example.com:5000/foo/bar",
			expectedTag:  "",
		},
		"Simple image with tag": {
			image:        "foo/bar:latest",
			expectedRepo: "foo/bar",
			expectedTag:  "latest",
		},
		"Simple image without path with tag": {
			image:        "foo:latest",
			expectedRepo: "foo",
			expectedTag:  "latest",
		},
		"Simple image without tag": {
			image:        "foo/bar",
			expectedRepo: "foo/bar",
			expectedTag:  "",
		},
		"Empty string": {
			image:        "",
			expectedRepo: "",
			expectedTag:  "",
		},
		"Digest based image": {
			image:        "registry.example.com:5000/foo/bar@sha256:abc123",
			expectedRepo: "registry.example.com:5000/foo/bar",
			expectedTag:  "",
		},
		"Both tag and digest": {
			image:        "registry.example.com:5000/foo/bar:latest@sha256:abc123",
			expectedRepo: "registry.example.com:5000/foo/bar",
			expectedTag:  "latest",
		},
		"Multi-level path with registry port and tag": {
			image:        "registry.example.com:5000/org/project/image:v1.2.3",
			expectedRepo: "registry.example.com:5000/org/project/image",
			expectedTag:  "v1.2.3",
		},
		"Localhost with port and tag": {
			image:        "localhost:5000/myimage:latest",
			expectedRepo: "localhost:5000/myimage",
			expectedTag:  "latest",
		},
	}

	for name, tc := range tCases {
		t.Run(name, func(t *testing.T) {
			repo, tag := parseImageRepoTag(tc.image)
			assert.Equal(t, tc.expectedRepo, repo)
			assert.Equal(t, tc.expectedTag, tag)
		})
	}
}
