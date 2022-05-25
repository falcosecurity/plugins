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

Name | Type | Description
:----|:-----|:-----------
`ka.auditid` | string | The unique id of the audit event
`ka.stage` | string | Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)
`ka.auth.decision` | string | The authorization decision
`ka.auth.reason` | string | The authorization reason
`ka.user.name` | string | The user name performing the request
`ka.user.groups` | string | The groups to which the user belongs
`ka.impuser.name` | string | The impersonated user name
`ka.verb` | string | The action being performed
`ka.uri` | string | The request URI as sent from client to server
`ka.uri.param` | string | The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, ka.uri.param[key] is val).
`ka.target.name` | string | The target object name
`ka.target.namespace` | string | The target object namespace
`ka.target.resource` | string | The target object resource
`ka.target.subresource` | string | The target object subresource
`ka.req.binding.subjects` | string | When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding
`ka.req.binding.role` | string | When the request object refers to a cluster role binding, the role being linked by the binding
`ka.req.binding.subject.has_name` | string | Deprecated, always returns "N/A". Only provided for backwards compatibility
`ka.req.configmap.name` | string | If the request object refers to a configmap, the configmap name
`ka.req.configmap.obj` | string | If the request object refers to a configmap, the entire configmap object
`ka.req.pod.containers.image` | string | When the request object refers to a pod, the container's images.
`ka.req.container.image` | string | Deprecated by ka.req.pod.containers.image. Returns the image of the first container only
`ka.req.pod.containers.image.repository` | string | The same as req.container.image, but only the repository part (e.g. falcosecurity/falco).
`ka.req.container.image.repository` | string | Deprecated by ka.req.pod.containers.image.repository. Returns the repository of the first container only
`ka.req.pod.host_ipc` | string | When the request object refers to a pod, the value of the hostIPC flag.
`ka.req.pod.host_network` | string | When the request object refers to a pod, the value of the hostNetwork flag.
`ka.req.container.host_network` | string | Deprecated alias for ka.req.pod.host_network
`ka.req.pod.host_pid` | string | When the request object refers to a pod, the value of the hostPID flag.
`ka.req.pod.containers.host_port` | string | When the request object refers to a pod, all container's hostPort values.
`ka.req.pod.containers.privileged` | string | When the request object refers to a pod, the value of the privileged flag for all containers.
`ka.req.container.privileged` | string | Deprecated by ka.req.pod.containers.privileged. Returns true if any container has privileged=true
`ka.req.pod.containers.allow_privilege_escalation` | string | When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all containers
`ka.req.pod.containers.read_only_fs` | string | When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all containers
`ka.req.pod.run_as_user` | string | When the request object refers to a pod, the runAsUser uid specified in the security context for the pod. See ....containers.run_as_user for the runAsUser for individual containers
`ka.req.pod.containers.run_as_user` | string | When the request object refers to a pod, the runAsUser uid for all containers
`ka.req.pod.containers.eff_run_as_user` | string | When the request object refers to a pod, the initial uid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified
`ka.req.pod.run_as_group` | string | When the request object refers to a pod, the runAsGroup gid specified in the security context for the pod. See ....containers.run_as_group for the runAsGroup for individual containers
`ka.req.pod.containers.run_as_group` | string | When the request object refers to a pod, the runAsGroup gid for all containers
`ka.req.pod.containers.eff_run_as_group` | string | When the request object refers to a pod, the initial gid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified
`ka.req.pod.containers.proc_mount` | string | When the request object refers to a pod, the procMount types for all containers
`ka.req.role.rules` | string | When the request object refers to a role/cluster role, the rules associated with the role
`ka.req.role.rules.apiGroups` | string | When the request object refers to a role/cluster role, the api groups associated with the role's rules
`ka.req.role.rules.nonResourceURLs` | string | When the request object refers to a role/cluster role, the non resource urls associated with the role's rules
`ka.req.role.rules.verbs` | string | When the request object refers to a role/cluster role, the verbs associated with the role's rules
`ka.req.role.rules.resources` | string | When the request object refers to a role/cluster role, the resources associated with the role's rules
`ka.req.pod.fs_group` | string | When the request object refers to a pod, the fsGroup gid specified by the security context.
`ka.req.pod.supplemental_groups` | string | When the request object refers to a pod, the supplementalGroup gids specified by the security context.
`ka.req.pod.containers.add_capabilities` | string | When the request object refers to a pod, all capabilities to add when running the container.
`ka.req.service.type` | string | When the request object refers to a service, the service type
`ka.req.service.ports` | string | When the request object refers to a service, the service's ports
`ka.req.pod.volumes.hostpath` | string | When the request object refers to a pod, all hostPath paths specified for all volumes
`ka.req.volume.hostpath` | string | Deprecated by ka.req.pod.volumes.hostpath. Return true if the provided (host) path prefix is used by any volume
`ka.req.pod.volumes.flexvolume_driver` | string | When the request object refers to a pod, all flexvolume drivers specified for all volumes
`ka.req.pod.volumes.volume_type` | string | When the request object refers to a pod, all volume types for all volumes
`ka.resp.name` | string | The response object name
`ka.response.code` | string | The response code
`ka.response.reason` | string | The response reason (usually present only for failures)
`ka.useragent` | string | The useragent of the client who made the request to the apiserver

## Usage

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: k8saudit
    library_path: libk8saudit.so
    init_config:
      maxEventBytes: 10485760
      sslCertificate: /etc/falco/falco.pem
    open_params: "http://:9765/k8s-audit"
  - name: json
    library_path: libjson.so
    init_config: ""

load_plugins: [k8saudit, json]
```

**Initialization Config**:
- `sslCertificate`: The SSL Certificate to be used with the HTTPS Webhook endpoint (Default: /etc/falco/falco.pem)
- `maxEventBytes`: Max size in bytes for an event JSON payload (Default: 10485760)

**Open Parameters**:
- `http://<host>:<port>/<endpoint>`: Opens an event stream by listening on a HTTP webserver
- `https://<host>:<port>/<endpoint>`: Opens an event stream by listening on a HTTPS webserver
- `no scheme`: Opens an event stream by reading the events from a file on the local filesystem. The params string is interpreted as a filepath


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
