package event

import "encoding/json"

type PortMapping struct {
	HostIp        string `json:"HostIp"`
	HostPort      string `json:"HostPort"`
	ContainerPort int    `json:"ContainerPort"`
}

type Mount struct {
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
	Propagation string `json:"Propagation"`
}

type Probe struct {
	Exe  string   `json:"exe"`
	Args []string `json:"args"`
}

type Container struct {
	Type             int               `json:"type"`
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Image            string            `json:"image"`
	ImageDigest      string            `json:"imagedigest"`
	ImageID          string            `json:"imageid"`
	ImageRepo        string            `json:"imagerepo"`
	ImageTag         string            `json:"imagetag"`
	User             string            `json:"User"`
	CniJson          string            `json:"cni_json"` // cri only
	CPUPeriod        int64             `json:"cpu_period"`
	CPUQuota         int64             `json:"cpu_quota"`
	CPUShares        int64             `json:"cpu_shares"`
	CPUSetCPUCount   int64             `json:"cpuset_cpu_count"`
	CreatedTime      int64             `json:"created_time"`
	Env              []string          `json:"env"`
	FullID           string            `json:"full_id"`
	HostIPC          bool              `json:"host_ipc"`
	HostNetwork      bool              `json:"host_network"`
	HostPID          bool              `json:"host_pid"`
	Ip               string            `json:"ip"`
	Size             int64             `json:"size"`
	IsPodSandbox     bool              `json:"is_pod_sandbox"`
	Labels           map[string]string `json:"labels"`
	MemoryLimit      int64             `json:"memory_limit"`
	SwapLimit        int64             `json:"swap_limit"`
	PodSandboxID     string            `json:"pod_sandbox_id"` // cri only
	Privileged       bool              `json:"privileged"`
	PodSandboxLabels map[string]string `json:"pod_sandbox_labels"` // cri only
	PortMappings     []PortMapping     `json:"port_mappings"`
	Mounts           []Mount           `json:"Mounts"`
	HealthcheckProbe *Probe            `json:"Healthcheck,omitempty"`
	LivenessProbe    *Probe            `json:"LivenessProbe,omitempty"`
	ReadinessProbe   *Probe            `json:"ReadinessProbe,omitempty"`
}

// Info struct wraps Container because we need the `container` struct in the json for backward compatibility.
// Format:
/*
{
  "container": {
    "type": 0,
    "id": "2400edb296c5",
    "name": "sharp_poincare",
    "image": "fedora:38",
    "imagedigest": "sha256:b9ff6f23cceb5bde20bb1f79b492b98d71ef7a7ae518ca1b15b26661a11e6a94",
    "imageid": "0ca0fed353fb77c247abada85aebc667fd1f5fa0b5f6ab1efb26867ba18f2f0a",
    "imagerepo": "fedora",
    "imagetag": "38",
    "User": "",
    "cni_json": "",
    "cpu_period": 0,
    "cpu_quota": 0,
    "cpu_shares": 0,
    "cpuset_cpu_count": 0,
    "created_time": 1730977803,
    "env": [
      "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "DISTTAG=f38container",
      "FGC=f38",
      "FBR=f38"
    ],
    "full_id": "2400edb296c5d631fef083a30c680f71801b0409a9676ee546c084d0087d7c7d",
    "host_ipc": false,
    "host_network": false,
    "host_pid": false,
    "ip": "",
    "is_pod_sandbox": false,
    "labels": {
      "maintainer": "Clement Verna <cverna@fedoraproject.org>"
    },
    "memory_limit": 0,
    "swap_limit": 0,
    "pod_sandbox_id": "",
    "privileged": false,
    "pod_sandbox_labels": null,
    "port_mappings": [],
    "Mounts": [
      {
        "Source": "/home/federico",
        "Destination": "/home/federico",
        "Mode": "",
        "RW": true,
        "Propagation": "rprivate"
      }
    ]
  }
}
*/
type Info struct {
	Container `json:"container"`
}

type Event struct {
	Info
	IsCreate bool
}

func (i *Info) String() string {
	str, err := json.Marshal(i)
	if err != nil {
		return ""
	}
	return string(str)
}
