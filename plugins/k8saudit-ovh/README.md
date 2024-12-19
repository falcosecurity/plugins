# Kubernetes Audit Events Plugin for OVHcloud

## Introduction

This plugin extends Falco to support [Kubernetes Audit Events](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-backends) from OVHcloud MKS clusters as a new data source.
For more details about what Audit logs are, see the [README of k8saudit plugin](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/README.md).

### Functionality

This plugin supports consuming Kubernetes Audit Events stored in OVHcloud Log Data Platform (LDP) for the MKS Clusters, see [OVHcloud official documentation](https://help.ovhcloud.com/csm/fr-public-cloud-kubernetes-forwarding-audit-logs?id=kb_article_view&sysparm_article=KB0062284) for details.

## Capabilities

The `k8saudit-ovh` uses the field extraction methods of the [`k8saudit`](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit) plugin as the format for the Audit Logs is same.

### Event Source

The event source for Kubernetes Audit Events from OVHcloud is `k8s_audit`, it allows to use same rules than `k8saudit` plugin.

### Supported Fields

Here is the current set of supported fields (from `k8saudit` plugin's extractor):
<!-- README-PLUGIN-FIELDS -->
|                        NAME                        |      TYPE       |      ARG      |                                                                                                 DESCRIPTION                                                                                                  |
|----------------------------------------------------|-----------------|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ka.auditid`                                       | `string`        | None          | The unique id of the audit event                                                                                                                                                                             |
| `ka.stage`                                         | `string`        | None          | Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)                                                                                                                                          |
| `ka.auth.decision`                                 | `string`        | None          | The authorization decision                                                                                                                                                                                   |
| `ka.auth.reason`                                   | `string`        | None          | The authorization reason                                                                                                                                                                                     |
| `ka.auth.openshift.decision`                       | `string`        | None          | The authentication decision of the openshfit apiserver extention. Only available on openshift clusters                                                                                                       |
| `ka.auth.openshift.username`                       | `string`        | None          | The user name performing the openshift authentication operation. Only available on openshift clusters                                                                                                        |
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

### Install the plugin

```bash
# Add falcosecurity index
sudo falcoctl index add falcosecurity https://falcosecurity.github.io/falcoctl/index.yaml
# Install k8saudit-ovh Falco plugin
sudo falcoctl artifact install k8saudit-ovh
```

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: k8saudit-ovh
    library_path: /usr/share/falco/plugins/libk8saudit-ovh.so
    open_params: "<OVH LDP WEBSOCKET URL>" # gra<x>.logs.ovh.com/tail/?tk=<ID>
  - name: json
    library_path: libjson.so
    init_config: ""
load_plugins: [k8saudit-ovh, json]
```
**Open Parameters**

A string which contains the LDP WebSocket URL of your OVHcloud MKS Cluster (required).

[Follow this guide](https://help.ovhcloud.com/csm/fr-logs-data-platform-ldp-tail?id=kb_article_view&sysparm_article=KB0037675#retrieve-your-websocket-address) to retrieve the OVHcloud LDP URL.

### Rules

The `k8saudit-ovh` plugin ships with no default rule for test purpose, you can use the same rules than those for `k8saudit` plugin. See [here](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml).


To test if it works anyway, you can still use this one for example:

```yaml
- required_engine_version: 15
- required_plugin_versions:
  - name: k8saudit-ovh
    version: 0.1.0

- rule: TEST
  desc: >
    Test rule
  condition: >
    ka.verb in (get,create,delete,update)
  output: verb=%ka.verb name=%ka.target.name resp=%ka.response.code namespace=%ka.target.namespace 
  priority: NOTICE
  source: k8s_audit
  tags: [k8s]
```

### Running locally

This plugin requires Falco with version >= **0.35.0**.

```bash
falco -c falco.yaml -r rules/k8s_audit_rules.yaml
```

```bash
12:29:51.895849000: Notice verb=get name=<NA> resp=200 namespace=<NA>
12:29:51.900789000: Notice verb=get name=<NA> resp=200 namespace=<NA>
^CEvents detected: 2
Rule counts by severity:
   NOTICE: 2
Triggered rules by rule name:
   TEST: 2
```

### Running in an OVHcloud MKS cluster

You can use the official [Falco Helm chart](https://github.com/falcosecurity/charts/tree/master/falco) to deploy it, with the following `values.yaml`:

```yaml
tty: true
kubernetes: false

# Just a Deployment with 1 replica (instead of a Daemonset) to have only one Pod that pulls the MKS Audit Logs from a OVHcloud LDP
controller:
  kind: deployment
  deployment:
    replicas: 1

falco:
  rules_files:
    - /etc/falco/k8s_audit_rules.yaml
    - /etc/falco/rules.d
  plugins:
    - name: k8saudit-ovh
      library_path: libk8saudit-ovh.so
      open_params: "gra<x>.logs.ovh.com/tail/?tk=<ID>" # Replace with your LDP Websocket URL
    - name: json
      library_path: libjson.so
      init_config: ""
  # Plugins that Falco will load. Note: the same plugins are installed by the falcoctl-artifact-install init container.
  load_plugins: [k8saudit-ovh, json]

driver:
  enabled: false
collectors:
  enabled: false

# use falcoctl to install automatically the plugin and the rules
falcoctl:
  artifact:
    install:
      enabled: true
    follow:
      enabled: true
  config:
    indexes:
    - name: falcosecurity
      url: https://falcosecurity.github.io/falcoctl/index.yaml
    artifact:
      allowedTypes:
        - plugin
        - rulesfile
      install:
        resolveDeps: false
        refs: [k8saudit-rules:0, k8saudit-ovh:0.1, json:0]
      follow:
        refs: [k8saudit-rules:0]
```

Note: You can also install Falcosidekick and enable the webUI to watch your events in an interface.
