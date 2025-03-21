# Container metadata enrichment Plugin

## Experimental

Consider this plugin as experimental until it reaches version `1.0.0`. By 'experimental' we mean that, although the plugin is functional and tested, it is currently in active development and may undergo changes in behavior as necessary, without prioritizing backward compatibility.

## Introduction

The `container` plugin enhances the Falco syscall source by providing additional information about container resources involved. You can find the comprehensive list of supported fields [here](#supported-fields).

### Functionality

The plugin itself reimplements all the container-related logic that was already present in libs under the form of a plugin, that can be attached to any source.  
Moreover, it aims to fix issues present in the current implementation, trying to be as quick as possible to gather container metadata information, to avoid losing 
a single event metadata.

## Capabilities

The `container` plugin implements the following capabilities:

* `capture listening` -> to attach `container_id` foreign key to all pre-existing threadinfos, once they have been scraped from procfs by sinsp 
* `extraction` -> to extract `container.X` fields
* `parsing` -> to parse `async` and `container` events (the latter for backward compatibility with existing scap files), and clone/fork/execve events to attach `container_id` foreign key to any threads
* `async` -> to generate events with container information and `dump` current plugin cache state when requested

It requires **3.10.0** plugin API version.

## Architecture

![](./architecture.svg)

The `container` plugin is split into 2 modules:
* a [C++ shared object](src) that implements the 3 capabilities and holds the cache map `<container_id,container_info>`
* a [GO static library](go-worker) (linked inside the C++ shared object) that implements the worker logic to retrieve new containers' metadata leveraging existing SDKs

As soon as the plugin starts, the go-worker gets started as part of the `async` capability, passing to it plugin init config and a C++ callback to generate async events. 
Whenever the GO worker finds a new container, it immediately generates an `async` event through the aforementioned callback.
The `async` event is then received by the C++ side as part of the `parsing` capability, and it enriches its own internal state cache.
Every time a clone/fork/execve event gets parsed, we attach to its thread table entry the information about the container_id, extracted by looking at the `cgroups` field, in a foreign key.
Once the extraction is requested for a thread, the container_id is then used as key to access our plugin's internal container metadata cache, and the requested infos extracted.

Note, however, that for some container engines, namely `{bpm,lxc,libvirt_lcx}`, we only support fetching generic info, ie: the container ID and the container type.  
Given that there is no "listener" SDK to attach to, for these engines the `async` event is generated directly by the C++ code, as soon as the container ID is retrieved.

### Plugin official name

`container`

### Supported Fields

<!-- README-PLUGIN-FIELDS -->
| NAME                                | TYPE      | ARG                  | DESCRIPTION                                |
|-------------------------------------|-----------|----------------------|--------------------------------------------|
| `container.id`                      | `string`  | None                 | Container ID (first 12B).                  |
| `container.full_id`                 | `string`  | None                 | Container ID.                              |
| `container.name`                    | `string`  | None                 | Container name.                            |
| `container.image`                   | `string`  | None                 | Image name.                                |
| `container.image.id`                | `string`  | None                 | Image ID.                                  |
| `container.type`                    | `string`  | None                 | Type.                                      |
| `container.privileged`              | `bool`    | None                 | Privileged.                                |
| `container.mounts`                  | `string`  | None                 | Mounts.                                    |
| `container.mount`                   | `string`  | Idx or Key, Required | Mount.                                     |
| `container.mount.source`            | `string`  | Idx or Key, Required | Mount Source.                              |
| `container.mount.dest`              | `string`  | Idx or Key, Required | Mount Destination.                         |
| `container.mount.mode`              | `string`  | Idx or Key, Required | Mount Mode.                                |
| `container.mount.rdwr`              | `string`  | Idx or Key, Required | Mount Read/Write.                          |
| `container.mount.propagation`       | `string`  | Idx or Key, Required | Mount Propagation.                         |
| `container.image.repository`        | `string`  | None                 | Repository.                                |
| `container.image.tag`               | `string`  | None                 | Image Tag.                                 |
| `container.image.digest`            | `string`  | None                 | Registry Digest.                           |
| `container.healthcheck`             | `string`  | None                 | Health Check.                              |
| `container.liveness_probe`          | `string`  | None                 | Liveness.                                  |
| `container.readiness_probe`         | `string`  | None                 | Readiness.                                 |
| `container.start_ts`                | `abstime` | None                 | Container start.                           |
| `container.duration`                | `reltime` | None                 | Container duration.                        |
| `container.ip`                      | `string`  | None                 | Container IP.                              |
| `container.cni.json`                | `string`  | None                 | Container's / pod's CNI result json.       |
| `container.host_pid`                | `bool`    | None                 | Host PID Namespace.                        |
| `container.host_network`            | `bool`    | None                 | Host Network Namespace.                    |
| `container.host_ipc`                | `bool`    | None                 | Host IPC Namespace.                        |
| `container.label`                   | `string`  | Key, Required        | Container Label                            |
| `container.labels`                  | `string`  | None                 | Container Labels                           |
| `proc.is_container_healthcheck`     | `bool`    | None                 | Process Is Container Healthcheck.          |
| `proc.is_container_liveness_probe`  | `bool`    | None                 | Process Is Container Liveness.             |
| `proc.is_container_readiness_probe` | `bool`    | None                 | Process Is Container Readiness.            |
| `k8s.pod.name`                      | `string`  | None                 | Pod Name                                   |
| `k8s.ns.name`                       | `string`  | None                 | Namespace Name                             |
| `k8s.pod.id`                        | `string`  | None                 | Legacy Pod ID                              |
| `k8s.pod.uid`                       | `string`  | None                 | Pod UID                                    |
| `k8s.pod.sandbox_id`                | `string`  | None                 | Pod / Sandbox ID (first 12 chars)          |
| `k8s.pod.full_sandbox_id`           | `string`  | None                 | Pod / Sandbox ID                           |
| `k8s.pod.label`                     | `string`  | Key, Required        | Pod Label                                  |
| `k8s.pod.labels`                    | `string`  | None                 | Pod Labels                                 |
| `k8s.pod.ip`                        | `string`  | None                 | Pod Ip                                     |
| `k8s.pod.cni.json`                  | `string`  | None                 | Pod CNI result json                        |
| `k8s.rc.name`                       | `string`  | None                 | [Deprecated] Replication Controller Name   |
| `k8s.rc.id`                         | `string`  | None                 | [Deprecated] Replication Controller ID     |
| `k8s.rc.label`                      | `string`  | Key, Required        | [Deprecated] Replication Controller Label  |
| `k8s.rc.labels`                     | `string`  | None                 | [Deprecated] Replication Controller Labels |
| `k8s.svc.name`                      | `string`  | None                 | [Deprecated] Service Name                  |
| `k8s.svc.id`                        | `string`  | None                 | [Deprecated] Service ID                    |
| `k8s.svc.label`                     | `string`  | Key, Required        | [Deprecated] Service Label                 |
| `k8s.svc.labels`                    | `string`  | None                 | [Deprecated] Service Labels                |
| `k8s.ns.id`                         | `string`  | None                 | [Deprecated] Namespace ID                  |
| `k8s.ns.label`                      | `string`  | Key, Required        | [Deprecated] Namespace Label               |
| `k8s.ns.labels`                     | `string`  | None                 | [Deprecated] Namespace Labels              |
| `k8s.rs.name`                       | `string`  | None                 | [Deprecated] Replica Set Name              |
| `k8s.rs.id`                         | `string`  | None                 | [Deprecated] Replica Set ID                |
| `k8s.rs.label`                      | `string`  | Key, Required        | [Deprecated] Replica Set Label             |
| `k8s.rs.labels`                     | `string`  | None                 | [Deprecated] Replica Set Labels            |
| `k8s.deployment.name`               | `string`  | None                 | [Deprecated] Deployment Name               |
| `k8s.deployment.id`                 | `string`  | None                 | [Deprecated] Deployment ID                 |
| `k8s.deployment.label`              | `string`  | Key, Required        | [Deprecated] Deployment Label              |
| `k8s.deployment.labels`             | `string`  | None                 | [Deprecated] Deployment Labels             |
 
<!-- /README-PLUGIN-FIELDS -->

## Requirements

* `containerd` >= 1.7 (https://kubernetes.io/docs/tasks/administer-cluster/switch-to-evented-pleg/, https://github.com/containerd/containerd/pull/7073)
* `cri-o` >= 1.26 (https://kubernetes.io/docs/tasks/administer-cluster/switch-to-evented-pleg/)
* `podman` >= v4.0.0 (2.0.0 introduced https://github.com/containers/podman/commit/165aef7766953cd0c0589ffa1abc25022a905adb, but the client library requires 4.0.0)

## Usage

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: container
    # path to the plugin .so file
    library_path: libcontainer.so
    init_config:
      label_max_len: 100 # (optional, default: 100; container labels larger than this won't be reported)
      with_size: false # (optional, default: false; whether to enable container size inspection, which is inherently slow)
      engines:
        docker:
          enabled: true
          sockets: ['/var/run/docker.sock']
        podman:
          enabled: true
          sockets: ['/run/podman/podman.sock', '/run/user/1000/podman/podman.sock']
        containerd:
          enabled: true
          sockets: ['/run/containerd/containerd.sock']
        cri:
          enabled: true
          sockets: ['/run/crio/crio.sock']
        lxc:
          enabled: false
        libvirt_lxc:
          enabled: false
        bpm:
          enabled: false  

load_plugins: [container]
```

By default, all engines are enabled on **default sockets**:
* Docker: `/var/run/docker.sock`
* Podman: `/run/podman/podman.sock` for root, + `/run/user/$uid/podman/podman.sock` for each user in the system
* Containerd: [`/run/containerd/containerd.sock`, `/run/k3s/containerd/containerd.sock`, `/run/host-containerd/containerd.sock`]
* Cri: `/run/crio/crio.sock`

### Rules

This plugin doesn't provide any custom rule, you can use the default Falco ruleset and add the necessary `container` fields.
Note: leveraging latest plugin SDK features, the plugin itself will expose certain fields as suggested output fields:
* `container.id`
* `container.name`

### Running

This plugin requires Falco with version >= **0.41.0**.
The plugin is bundled within Falco, so you only need to run Falco as you would do normally.

## Local development

### Build and test

Build the plugin on a fresh `Ubuntu 22.04` machine:

```bash
sudo apt update -y
sudo apt install -y cmake build-essential autoconf libtool pkg-config
git clone https://github.com/falcosecurity/plugins.git
cd plugins/container
make libcontainer.so
```

You can also run `make exe` from withing the `go-worker` folder to build a `worker` executable to test the go-worker implementation.