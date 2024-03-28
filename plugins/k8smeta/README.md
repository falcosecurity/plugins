# Kubernetes metadata enrichment Plugin

## Experimental

Consider this plugin as experimental until it reaches version `1.0.0`. By 'experimental' we mean that, although the plugin is functional and tested, it is currently in active development and may undergo changes in behavior as necessary, without prioritizing backward compatibility.

## Introduction

The `k8smeta` plugin enhances the Falco syscall source by providing additional information about the Kubernetes resources involved. For instance, when a syscall is thrown within a pod, it allows retrieving details about the pod, such as `uid`, `name`, `labels`, and more. It also provides information about resources associated with the pod like `deployments`, `services`, `replica-sets`, and others. You can find the comprehensive list of supported fields [here](#supported-fields).

### Functionality

The plugin gathers details about Kubernetes resources from a remote collector known as [`k8s-metacollector`](https://github.com/falcosecurity/k8s-metacollector). It then stores this information in tables and provides access to Falco upon request. The plugin specifically acquires data for the node where the associated Falco instance is deployed, resulting in node-level granularity. In contrast, the collector runs at the cluster level. This implies that within a given cluster, there may be multiple `k8smeta` plugins (one per node), but there is only one collector.

## Capabilities

The `k8smeta` plugin implements 3 capabilities:

* `extraction`
* `parsing`
* `async`

### Plugin official name

`k8smeta`

### Supported Fields

<!-- README-PLUGIN-FIELDS -->
|            NAME             |      TYPE       |      ARG      |                                                                                                                                                  DESCRIPTION                                                                                                                                                  |
|-----------------------------|-----------------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `k8smeta.pod.name`          | `string`        | None          | Kubernetes pod name.                                                                                                                                                                                                                                                                                          |
| `k8smeta.pod.uid`           | `string`        | None          | Kubernetes pod UID.                                                                                                                                                                                                                                                                                           |
| `k8smeta.pod.label`         | `string`        | Key, Required | Kubernetes pod label. E.g. 'k8smeta.pod.label[foo]'.                                                                                                                                                                                                                                                          |
| `k8smeta.pod.labels`        | `string (list)` | None          | Kubernetes pod comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                                                |
| `k8smeta.pod.ip`            | `string`        | None          | Kubernetes pod ip                                                                                                                                                                                                                                                                                             |
| `k8smeta.ns.name`           | `string`        | None          | Kubernetes namespace name.                                                                                                                                                                                                                                                                                    |
| `k8smeta.ns.uid`            | `string`        | None          | Kubernetes namespace UID.                                                                                                                                                                                                                                                                                     |
| `k8smeta.ns.label`          | `string`        | Key, Required | Kubernetes namespace label. E.g. 'k8smeta.ns.label[foo]'.                                                                                                                                                                                                                                                     |
| `k8smeta.ns.labels`         | `string (list)` | None          | Kubernetes namespace comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                                          |
| `k8smeta.deployment.name`   | `string`        | None          | Kubernetes deployment name.                                                                                                                                                                                                                                                                                   |
| `k8smeta.deployment.uid`    | `string`        | None          | Kubernetes deployment UID.                                                                                                                                                                                                                                                                                    |
| `k8smeta.deployment.label`  | `string`        | Key, Required | Kubernetes deployment label. E.g. 'k8smeta.rs.label[foo]'.                                                                                                                                                                                                                                                    |
| `k8smeta.deployment.labels` | `string (list)` | None          | Kubernetes deployment comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                                         |
| `k8smeta.svc.name`          | `string (list)` | None          | Kubernetes services name. Return a list with all the names of the services associated with the current pod. E.g. '(service1,service2)'                                                                                                                                                                        |
| `k8smeta.svc.uid`           | `string (list)` | None          | Kubernetes services UID. Return a list with all the UIDs of the services associated with the current pod. E.g. '(88279776-941c-491e-8da1-95ef30f50fe8,149e72f4-a570-4282-bfa0-25307c5007e8)'                                                                                                                  |
| `k8smeta.svc.label`         | `string (list)` | Key, Required | Kubernetes services label. If the services associated with the current pod have a label with this name, return the list of label's values. E.g. if the current pod has 2 services associated and both have the 'foo' label, 'k8smeta.svc.label[foo]' will return '(service1-label-value,service2-label-value) |
| `k8smeta.svc.labels`        | `string (list)` | None          | Kubernetes services labels. Return a list with all the comma-separated key/value labels of the services associated with the current pod. E.g. '(foo1:bar1,foo2:bar2)'                                                                                                                                         |
| `k8smeta.rs.name`           | `string`        | None          | Kubernetes replica set name.                                                                                                                                                                                                                                                                                  |
| `k8smeta.rs.uid`            | `string`        | None          | Kubernetes replica set UID.                                                                                                                                                                                                                                                                                   |
| `k8smeta.rs.label`          | `string`        | Key, Required | Kubernetes replica set label. E.g. 'k8smeta.rs.label[foo]'.                                                                                                                                                                                                                                                   |
| `k8smeta.rs.labels`         | `string (list)` | None          | Kubernetes replica set comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                                        |
| `k8smeta.rc.name`           | `string`        | None          | Kubernetes replication controller name.                                                                                                                                                                                                                                                                       |
| `k8smeta.rc.uid`            | `string`        | None          | Kubernetes replication controller UID.                                                                                                                                                                                                                                                                        |
| `k8smeta.rc.label`          | `string`        | Key, Required | Kubernetes replication controller label. E.g. 'k8smeta.rc.label[foo]'.                                                                                                                                                                                                                                        |
| `k8smeta.rc.labels`         | `string (list)` | None          | Kubernetes replication controller comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                             |
<!-- /README-PLUGIN-FIELDS -->

## Usage

### Configuration

Here's an example of configuration of `falco.yaml`:

> NOTE: Please note that you can provide values to the config as environment variables. So, for example, you can take advantage of the Kubernetes downward API to provide the node name as an env variable `nodename: ${MY_NODE}`.

```yaml
plugins:
  - name: k8smeta
    # path to the plugin .so file
    library_path: libk8smeta.so
    init_config:
      # port exposed by the k8s-metacollector (required)
      collectorPort: 45000
      # hostname exposed by the k8s-metacollector (required)
      collectorHostname: localhost
      # name of the node on which the Falco instance is running. (required)
      nodeName: kind-control-plane
      # verbosity level for the plugin logger (optional)
      verbosity: warn # (default: info)
      # path to the PEM encoding of the server root certificates. (optional)
      # Used to open an authanticated GRPC channel with the collector.
      # If empty the connection will be insecure.
      caPEMBundle: /etc/ssl/certs/ca-certificates.crt 

load_plugins: [k8smeta]
```

**Initialization Config**:

See the [configuration](#configuration) section above.

**Open Parameters**:

The plugin doesn't have open params

### Rules

This plugin doesn't provide any custom rule, you can use the default Falco ruleset and add the necessary `k8smeta` fields. A very simple example rule can be found [here](https://github.com/falcosecurity/plugins/blob/main/plugins/k8smeta/test/rules/example_rule.yaml)

### Running

This plugin requires Falco with version >= **0.37.0**.
Modify the `falco.yaml` with the [configuration above](#configuration) and you are ready to go!

```shell
falco -c falco.yaml -r falco_rules.yaml
```

## Local development

### Build and test

Build the plugin on a fresh `Ubuntu 22.04` machine:

```bash
sudo apt update -y
sudo apt install -y cmake build-essential autoconf libtool pkg-config
git clone https://github.com/falcosecurity/plugins.git
cd plugins/k8smeta
mkdir build && cd build
cmake ..
make k8smeta -j10
```

To run local tests follow the steps [here](https://github.com/falcosecurity/plugins/blob/main/plugins/k8smeta/test/README.md)
