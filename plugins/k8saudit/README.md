# Kubernetes Audit Events Plugin

## Introduction

This plugin extends Falco to support [Kubernetes Audit Events](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-backends) as a new data source.
Audit events are logged by the API server when almost every cluster management task is performed. By monitoring the audit logs, this plugins provides high visibility over the activity in your cluster allows detecting malicious behavior.

Support for Kubernetes Audit Events was previously introduced in Falco v0.13 as a parallel independent stream of events that was read separately from system calls, and was matched separately against its own sets of rules.
This legacy implementation resided in the Falco codebase and hooked into many points of libsinsp. This plugin is a direct porting of that feature by leveraging the Falco Plugin System introduced in [Falco 0.31](https://falco.org/blog/falco-0-31-0/).
The plugin implementation is a 1-1 porting of the legacy implementation supported by Falco, with few breaking changes introduced to solve few cases of ambiguous behavior and to comply to the constraints of libsinsp and the plugin system.

### Functionality

This plugin supports consuming Kubernetes Audit Events coming from the [Webhook backend](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/#webhook-backend) or from file. For webhooks, the plugin embeds a webserver that listens on a configurable port and accepts POST requests. The posted JSON object comprises one or more events. The webserver of the plugin can be configuted as part of the plugin's init configuration and open parameters. For files, the plugins expects content to be [in JSONL format](https://jsonlines.org/), where each line represents a JSON object, containing one or more audit events.

The expected way of using the plugin is through Webhook. The file reading support is mostly designed for testing purposes and for development, but does not represent a concrete deployment use case.

## Capabilities

The `k8saudit` plugin implements both the event sourcing and the field extraction capabilities of the Falco Plugin System.

### Event Source

The event source for Kubernetes Audit Events is `k8s_audit`.

### Supported Fields

<!-- README-PLUGIN-FIELDS -->
|                        NAME                        |      TYPE       |      ARG      |                                                                                                 DESCRIPTION                                                                                                  |
|----------------------------------------------------|-----------------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ka.auditid`                                       | `string`        | None          | The unique id of the audit event                                                                                                                                                                             |
| `ka.stage`                                         | `string`        | None          | Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)                                                                                                                                          |
| `ka.auth.decision`                                 | `string`        | None          | The authorization decision                                                                                                                                                                                   |
| `ka.auth.reason`                                   | `string`        | None          | The authorization reason                                                                                                                                                                                     |
| `ka.auth.openshift.decision`                       | `string`        | None          | The authentication decision of the openshfit apiserver extention. Only available on openshift clusters                                                                                                       |
| `ka.auth.openshift.username`                       | `string`        | None          | The user name performing the openshift authentication operation. Only available on openshift clusters                                                                                                        |
| `ka.validations.admission.policy.failure`          | `string`        | None          | The validation failure reason from a Validation Admission Policy                                                                                                                                             |
| `ka.user.name`                                     | `string`        | None          | The user name performing the request                                                                                                                                                                         |
| `ka.user.groups`                                   | `string (list)` | None          | The groups to which the user belongs                                                                                                                                                                         |
| `ka.impuser.name`                                  | `string`        | None          | The impersonated user name                                                                                                                                                                                   |
| `ka.verb`                                          | `string`        | None          | The action being performed                                                                                                                                                                                   |
| `ka.uri`                                           | `string`        | None          | The request URI as sent from client to server                                                                                                                                                                |
| `ka.uri.param`                                     | `string`        | Key, Required | The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, ka.uri.param[key] is val).                                                                                                      |
| `ka.target.name`                                   | `string`        | None          | The target object name                                                                                                                                                                                       |
| `ka.target.namespace`                              | `string`        | None          | The target object namespace                                                                                                                                                                                  |
| `ka.target.resource`                               | `string`        | None          | The target object resource                                                                                                                                                                                   |
| `ka.target.subresource`                            | `string`        | None          | The target object subresource                                                                                                                                                                                |
| `ka.target.pod.name`                               | `string`        | None          | The target pod name                                                                                                                                                                                          |
| `ka.req.binding.subjects`                          | `string (list)` | None          | When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding                                                                                       |
| `ka.req.binding.subjects.user_names`               | `string (list)` | None          | When the request object refers to a cluster role binding, the subject user names being linked by the binding                                                                                                 |
| `ka.req.binding.subjects.serviceaccount_names`     | `string (list)` | None          | When the request object refers to a cluster role binding, the subject service account names being linked by the binding                                                                                      |
| `ka.req.binding.subjects.serviceaccount_ns_names`  | `string (list)` | None          | When the request object refers to a cluster role binding, the subject serviceaccount namespaced names being linked by the binding, e.g. a list containing: mynamespace:myserviceaccount                      |
| `ka.req.binding.subjects.group_names`              | `string (list)` | None          | When the request object refers to a cluster role binding, the subject group names being linked by the binding                                                                                                |
| `ka.req.binding.role`                              | `string`        | None          | When the request object refers to a cluster role binding, the role being linked by the binding                                                                                                               |
| `ka.req.binding.subject.has_name`                  | `string`        | Key, Required | Deprecated, always returns "N/A". Only provided for backwards compatibility                                                                                                                                  |
| `ka.req.configmap.name`                            | `string`        | None          | If the request object refers to a configmap, the configmap name                                                                                                                                              |
| `ka.req.configmap.obj`                             | `string`        | None          | If the request object refers to a configmap, the entire configmap object                                                                                                                                     |
| `ka.req.pod.containers.image`                      | `string (list)` | Index         | When the request object refers to a pod, the container's images.                                                                                                                                             |
| `ka.req.container.image`                           | `string`        | None          | Deprecated by ka.req.pod.containers.image. Returns the image of the first container only                                                                                                                     |
| `ka.req.pod.containers.image.repository`           | `string (list)` | Index         | The same as req.container.image, but only the repository part (e.g. falcosecurity/falco).                                                                                                                    |
| `ka.req.container.image.repository`                | `string`        | None          | Deprecated by ka.req.pod.containers.image.repository. Returns the repository of the first container only                                                                                                     |
| `ka.req.pod.host_ipc`                              | `string`        | None          | When the request object refers to a pod, the value of the hostIPC flag.                                                                                                                                      |
| `ka.req.pod.host_network`                          | `string`        | None          | When the request object refers to a pod, the value of the hostNetwork flag.                                                                                                                                  |
| `ka.req.container.host_network`                    | `string`        | None          | Deprecated alias for ka.req.pod.host_network                                                                                                                                                                 |
| `ka.req.pod.host_pid`                              | `string`        | None          | When the request object refers to a pod, the value of the hostPID flag.                                                                                                                                      |
| `ka.req.pod.containers.host_port`                  | `string (list)` | Index         | When the request object refers to a pod, all container's hostPort values.                                                                                                                                    |
| `ka.req.pod.containers.privileged`                 | `string (list)` | Index         | When the request object refers to a pod, the value of the privileged flag for all containers.                                                                                                                |
| `ka.req.container.privileged`                      | `string`        | None          | Deprecated by ka.req.pod.containers.privileged. Returns true if any container has privileged=true                                                                                                            |
| `ka.req.pod.containers.allow_privilege_escalation` | `string (list)` | Index         | When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all containers                                                                                                   |
| `ka.req.pod.containers.read_only_fs`               | `string (list)` | Index         | When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all containers                                                                                                     |
| `ka.req.pod.run_as_user`                           | `string`        | None          | When the request object refers to a pod, the runAsUser uid specified in the security context for the pod. See ....containers.run_as_user for the runAsUser for individual containers                         |
| `ka.req.pod.containers.run_as_user`                | `string (list)` | Index         | When the request object refers to a pod, the runAsUser uid for all containers                                                                                                                                |
| `ka.req.pod.containers.eff_run_as_user`            | `string (list)` | Index         | When the request object refers to a pod, the initial uid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified |
| `ka.req.pod.run_as_group`                          | `string`        | None          | When the request object refers to a pod, the runAsGroup gid specified in the security context for the pod. See ....containers.run_as_group for the runAsGroup for individual containers                      |
| `ka.req.pod.containers.run_as_group`               | `string (list)` | Index         | When the request object refers to a pod, the runAsGroup gid for all containers                                                                                                                               |
| `ka.req.pod.containers.eff_run_as_group`           | `string (list)` | Index         | When the request object refers to a pod, the initial gid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified |
| `ka.req.pod.containers.proc_mount`                 | `string (list)` | Index         | When the request object refers to a pod, the procMount types for all containers                                                                                                                              |
| `ka.req.role.rules`                                | `string (list)` | None          | When the request object refers to a role/cluster role, the rules associated with the role                                                                                                                    |
| `ka.req.role.rules.apiGroups`                      | `string (list)` | Index         | When the request object refers to a role/cluster role, the api groups associated with the role's rules                                                                                                       |
| `ka.req.role.rules.nonResourceURLs`                | `string (list)` | Index         | When the request object refers to a role/cluster role, the non resource urls associated with the role's rules                                                                                                |
| `ka.req.role.rules.verbs`                          | `string (list)` | Index         | When the request object refers to a role/cluster role, the verbs associated with the role's rules                                                                                                            |
| `ka.req.role.rules.resources`                      | `string (list)` | Index         | When the request object refers to a role/cluster role, the resources associated with the role's rules                                                                                                        |
| `ka.req.pod.fs_group`                              | `string`        | None          | When the request object refers to a pod, the fsGroup gid specified by the security context.                                                                                                                  |
| `ka.req.pod.supplemental_groups`                   | `string (list)` | None          | When the request object refers to a pod, the supplementalGroup gids specified by the security context.                                                                                                       |
| `ka.req.pod.containers.add_capabilities`           | `string (list)` | Index         | When the request object refers to a pod, all capabilities to add when running the container.                                                                                                                 |
| `ka.req.service.type`                              | `string`        | None          | When the request object refers to a service, the service type                                                                                                                                                |
| `ka.req.service.ports`                             | `string (list)` | Index         | When the request object refers to a service, the service's ports                                                                                                                                             |
| `ka.req.pod.volumes.hostpath`                      | `string (list)` | Index         | When the request object refers to a pod, all hostPath paths specified for all volumes                                                                                                                        |
| `ka.req.volume.hostpath`                           | `string`        | Key, Required | Deprecated by ka.req.pod.volumes.hostpath. Return true if the provided (host) path prefix is used by any volume                                                                                              |
| `ka.req.pod.volumes.flexvolume_driver`             | `string (list)` | Index         | When the request object refers to a pod, all flexvolume drivers specified for all volumes                                                                                                                    |
| `ka.req.pod.volumes.volume_type`                   | `string (list)` | Index         | When the request object refers to a pod, all volume types for all volumes                                                                                                                                    |
| `ka.resp.name`                                     | `string`        | None          | The response object name                                                                                                                                                                                     |
| `ka.response.code`                                 | `string`        | None          | The response code                                                                                                                                                                                            |
| `ka.response.reason`                               | `string`        | None          | The response reason (usually present only for failures)                                                                                                                                                      |
| `ka.useragent`                                     | `string`        | None          | The useragent of the client who made the request to the apiserver                                                                                                                                            |
| `ka.sourceips`                                     | `string (list)` | Index         | The IP addresses of the client who made the request to the apiserver                                                                                                                                         |
| `ka.cluster.name`                                  | `string`        | None          | The name of the k8s cluster                                                                                                                                                                                  |
<!-- /README-PLUGIN-FIELDS -->

## Usage

### Requirements

The Kubernetes cluster must have the [audit logs](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
enabled and configured to send the audit logs to the plugin. We provide the [audit-policy.yaml](./configs/audit-policy.yaml) which is tailored for the `k8saudit` plugin.
The [audit-policy.yaml](./configs/audit-policy.yaml) is of vital importance, it defines the rules about what events should
be recorded and what data they should include. The rules shipped with the `k8saudit` plugins relies on those events.
The [webhook-config.yaml](./configs/webhook-config.yaml.in) shows how to configure the webhook backend to send events to
an external HTTP API.

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: k8saudit
    library_path: libk8saudit.so
    init_config:
      sslCertificate: /etc/falco/falco.pem
    open_params: "http://:9765/k8s-audit"
  - name: json
    library_path: libjson.so
    init_config: ""

load_plugins: [k8saudit, json]
```

**Initialization Config**:
- `sslCertificate`: The SSL Certificate to be used with the HTTPS Webhook endpoint (Default: /etc/falco/falco.pem)
- `maxEventSize`: Maximum size of single audit event (Default: 262144)
- `webhookMaxBatchSize`: Maximum size of incoming webhook POST request bodies (Default: 12582912)
- `useAsync`: If true then async extraction optimization is enabled (Default: true)

**Open Parameters**:
- `http://<host>:<port>/<endpoint>`: Opens an event stream by listening on a HTTP webserver
- `https://<host>:<port>/<endpoint>`: Opens an event stream by listening on a HTTPS webserver
- `no scheme`: Opens an event stream by reading the events from a file on the local filesystem. The params string is interpreted as a filepath


**NOTE**: There is also a full tutorial on how to run the k8saudit plugin in a Kubernetes cluster using minikube: 
https://falco.org/docs/install-operate/third-party/learning/#falco-with-multiple-sources.

### Rules

The `k8saudit` plugin ships with a default set of ruleset (see `rules/` directory).
The official ruleset depends on the `json` plugin, which motivates its presence in the `falco.yaml` sample showed above.

### Running

This plugin requires Falco with version >= **0.32.0**.
```shell
falco -c falco.yaml -r k8s_audit_rules.yaml
```
```shell
14:09:12.581541000: Warning Pod started with privileged container (user=system:serviceaccount:kube-system:replicaset-controller pod=nginx-deployment-5cdcc99dbf-rgw6z ns=default image=nginx)
Driver Events:0
Driver Drops:0
Elapsed time: 0.004, Captured Events: 1, 224.62 eps
Events detected: 1
Rule counts by severity:
   WARNING: 1
Triggered rules by rule name:
   Create Privileged Pod: 1
Syscall event drop monitoring:
   - event drop detected: 0 occurrences
   - num times actions taken: 0
```
