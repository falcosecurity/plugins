# Kubernetes Audit Events Plugin

## Introduction

This plugin enriches Falco syscall flow with Kubernetes Metadata coming from the API server.
The plugin uses a GRPC channel to communicate with a remote [collector](https://github.com/falcosecurity/k8s-metacollector). The collector is indipendent from the plugin and should be deployed as a separate component. The main role of the plugin is to associate each syscall with information about the pod in which they are thrown.

### Functionality

TODO

## Capabilities

The `k8smeta` plugin implements these capabilities:
* `extraction`
* `parsing`
* `async`

### Supported Fields

<!-- README-PLUGIN-FIELDS -->
|            NAME            |      TYPE       |      ARG      |                                                                                                                                                 DESCRIPTION                                                                                                                                                  |
|----------------------------|-----------------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `k8sres.pod.name`          | `string`        | None          | Kubernetes pod name.                                                                                                                                                                                                                                                                                         |
| `k8sres.pod.id`            | `string`        | None          | Kubernetes pod ID.                                                                                                                                                                                                                                                                                           |
| `k8sres.pod.label`         | `string`        | Key, Required | Kubernetes pod label. E.g. 'k8sres.pod.label[foo]'.                                                                                                                                                                                                                                                          |
| `k8sres.pod.labels`        | `string (list)` | None          | Kubernetes pod comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                                               |
| `k8sres.pod.ip`            | `string`        | None          | Kubernetes pod ip                                                                                                                                                                                                                                                                                            |
| `k8sres.ns.name`           | `string`        | None          | Kubernetes namespace name.                                                                                                                                                                                                                                                                                   |
| `k8sres.ns.id`             | `string`        | None          | Kubernetes namespace ID.                                                                                                                                                                                                                                                                                     |
| `k8sres.ns.label`          | `string`        | Key, Required | Kubernetes namespace label. E.g. 'k8sres.ns.label[foo]'.                                                                                                                                                                                                                                                     |
| `k8sres.ns.labels`         | `string (list)` | None          | Kubernetes namespace comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                                         |
| `k8sres.deployment.name`   | `string`        | None          | Kubernetes deployment name.                                                                                                                                                                                                                                                                                  |
| `k8sres.deployment.id`     | `string`        | None          | Kubernetes deployment ID.                                                                                                                                                                                                                                                                                    |
| `k8sres.deployment.label`  | `string`        | Key, Required | Kubernetes deployment label. E.g. 'k8sres.rs.label[foo]'.                                                                                                                                                                                                                                                    |
| `k8sres.deployment.labels` | `string (list)` | None          | Kubernetes deployment comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                                        |
| `k8sres.svc.name`          | `string (list)` | None          | Kubernetes services name. Return a list with all the names of the services associated with the current pod. E.g. '(service1,service2)'                                                                                                                                                                       |
| `k8sres.svc.id`            | `string (list)` | None          | Kubernetes services ID. Return a list with all the IDs of the services associated with the current pod. E.g. '(88279776-941c-491e-8da1-95ef30f50fe8,149e72f4-a570-4282-bfa0-25307c5007e8)'                                                                                                                   |
| `k8sres.svc.label`         | `string (list)` | Key, Required | Kubernetes services label. If the services associated with the current pod have a label with this name, return the list of label's values. E.g. if the current pod has 2 services associated and both have the 'foo' label, 'k8sres.svc.label[foo]' will return '(service1-label-value,service2-label-value) |
| `k8sres.svc.labels`        | `string (list)` | None          | Kubernetes services labels. Return a list with all the comma-separated key/value labels of the services associated with the current pod. E.g. '(foo1:bar1,foo2:bar2)'                                                                                                                                        |
| `k8sres.rs.name`           | `string`        | None          | Kubernetes replica set name.                                                                                                                                                                                                                                                                                 |
| `k8sres.rs.id`             | `string`        | None          | Kubernetes replica set ID.                                                                                                                                                                                                                                                                                   |
| `k8sres.rs.label`          | `string`        | Key, Required | Kubernetes replica set label. E.g. 'k8sres.rs.label[foo]'.                                                                                                                                                                                                                                                   |
| `k8sres.rs.labels`         | `string (list)` | None          | Kubernetes replica set comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                                       |
| `k8sres.rc.name`           | `string`        | None          | Kubernetes replication controller name.                                                                                                                                                                                                                                                                      |
| `k8sres.rc.id`             | `string`        | None          | Kubernetes replication controller ID.                                                                                                                                                                                                                                                                        |
| `k8sres.rc.label`          | `string`        | Key, Required | Kubernetes replication controller label. E.g. 'k8sres.rc.label[foo]'.                                                                                                                                                                                                                                        |
| `k8sres.rc.labels`         | `string (list)` | None          | Kubernetes replication controller comma-separated key/value labels. E.g. '(foo1:bar1,foo2:bar2)'.                                                                                                                                                                                                            |
<!-- /README-PLUGIN-FIELDS -->

## Usage

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
load_plugins: [k8smeta]

plugins:
  - name: k8smeta
    library_path: libk8smeta.so
    init_config:
      collectorPort: 45000
      collectorHostname: localhost
      nodename: kind-control-plane
```

**Initialization Config**:

TODO

**Open Parameters**:

The plugin doesn't have open params

### Rule Example

To see how to use the plugin fields in a Falco rule check the example rule `/k8smeta/test/rules/example_rule.yaml`.
