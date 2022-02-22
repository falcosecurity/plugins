# K8S Audit Logs EKS

This repository contains the `k8s-audit-logs-eks` plugin for `Falco`, it collects `k8s audit logs` of an `EKS` cluster from `AWS Cloudwatch Logs`.

The plugin also exports fields that extract information from a `k8s audit` event, such as the stage, the verb, the response code, ...

- [K8S Audit Logs EKS](#k8s-audit-logs-eks)
- [Event Source](#event-source)
- [Supported Fields](#supported-fields)
- [Development](#development)
  - [Requirements](#requirements)
  - [Build](#build)
- [Settings](#settings)
- [Authentication to AWS](#authentication-to-aws)
- [Configuration files](#configuration-files)
- [Usage](#usage)
  - [Requirements](#requirements-1)
  - [Results](#results)

# Event Source

The event source for `k8s-audit-logs-eks` events is `k8s_audit_eks`.

# Supported Fields

| Name                                               | Type   | Description                                                                                                                                                                                                                             |
| -------------------------------------------------- | ------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ka.auditid`                                       | string | The unique id of the audit event                                                                                                                                                                                                        |
| `ka.stage`                                         | string | Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)                                                                                                                                                                     |
| `ka.auth.decision`                                 | string | The authorization decision                                                                                                                                                                                                              |
| `ka.auth.reason`                                   | string | The authorization reason                                                                                                                                                                                                                |
| `ka.user.name`                                     | string | The user name performing the request                                                                                                                                                                                                    |
| `ka.user.groups`                                   | string | The groups to which the user belongs                                                                                                                                                                                                    |
| `ka.impuser.name`                                  | string | The impersonated user name                                                                                                                                                                                                              |
| `ka.verb`                                          | string | The action being performed                                                                                                                                                                                                              |
| `ka.uri`                                           | string | The request URI as sent from client to server                                                                                                                                                                                           |
| `ka.uri.param`                                     | string | The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, ka.uri.param[key] is val). (IDX_REQUIRED, IDX_KEY)                                                                                                         |
| `ka.target.name`                                   | string | The target object name                                                                                                                                                                                                                  |
| `ka.target.namespace`                              | string | The target object namespace                                                                                                                                                                                                             |
| `ka.target.resource`                               | string | The target object resource                                                                                                                                                                                                              |
| `ka.target.subresource`                            | string | The target object subresource                                                                                                                                                                                                           |
| `ka.req.binding.subjects`                          | string | When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding                                                                                                                  |
| `ka.req.binding.role`                              | string | When the request object refers to a cluster role binding, the role being linked by the binding                                                                                                                                          |
| `ka.req.binding.subject.has_name`                  | string | Deprecated, always returns "N/A". Only provided for backwards compatibility (IDX_REQUIRED, IDX_KEY)                                                                                                                                     |
| `ka.req.configmap.name`                            | string | If the request object refers to a configmap, the configmap name                                                                                                                                                                         |
| `ka.req.configmap.obj`                             | string | If the request object refers to a configmap, the entire configmap object                                                                                                                                                                |
| `ka.req.pod.containers.image`                      | string | When the request object refers to a pod, the container's images. (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                                             |
| `ka.req.container.image`                           | string | Deprecated by ka.req.pod.containers.image. Returns the image of the first container only                                                                                                                                                |
| `ka.req.pod.containers.image.repository`           | string | The same as req.container.image, but only the repository part (e.g. falcosecurity/falco). (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                    |
| `ka.req.container.image.repository`                | string | Deprecated by ka.req.pod.containers.image.repository. Returns the repository of the first container only                                                                                                                                |
| `ka.req.pod.host_ipc`                              | string | When the request object refers to a pod, the value of the hostIPC flag.                                                                                                                                                                 |
| `ka.req.pod.host_network`                          | string | When the request object refers to a pod, the value of the hostNetwork flag.                                                                                                                                                             |
| `ka.req.container.host_network`                    | string | Deprecated alias for ka.req.pod.host_network                                                                                                                                                                                            |
| `ka.req.pod.host_pid`                              | string | When the request object refers to a pod, the value of the hostPID flag.                                                                                                                                                                 |
| `ka.req.pod.containers.host_port`                  | string | When the request object refers to a pod, all container's hostPort values. (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                                    |
| `ka.req.pod.containers.privileged`                 | string | When the request object refers to a pod, the value of the privileged flag for all containers. (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                |
| `ka.req.container.privileged`                      | string | Deprecated by ka.req.pod.containers.privileged. Returns true if any container has privileged=true                                                                                                                                       |
| `ka.req.pod.containers.allow_privilege_escalation` | string | When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all containers (IDX_ALLOWED, IDX_NUMERIC)                                                                                                   |
| `ka.req.pod.containers.read_only_fs`               | string | When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all containers (IDX_ALLOWED, IDX_NUMERIC)                                                                                                     |
| `ka.req.pod.run_as_user`                           | string | When the request object refers to a pod, the runAsUser uid specified in the security context for the pod. See ....containers.run_as_user for the runAsUser for individual containers                                                    |
| `ka.req.pod.containers.run_as_user`                | string | When the request object refers to a pod, the runAsUser uid for all containers (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                                |
| `ka.req.pod.containers.eff_run_as_user`            | string | When the request object refers to a pod, the initial uid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified (IDX_ALLOWED, IDX_NUMERIC) |
| `ka.req.pod.run_as_group`                          | string | When the request object refers to a pod, the runAsGroup gid specified in the security context for the pod. See ....containers.run_as_group for the runAsGroup for individual containers                                                 |
| `ka.req.pod.containers.run_as_group`               | string | When the request object refers to a pod, the runAsGroup gid for all containers (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                               |
| `ka.req.pod.containers.eff_run_as_group`           | string | When the request object refers to a pod, the initial gid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified (IDX_ALLOWED, IDX_NUMERIC) |
| `ka.req.pod.containers.proc_mount`                 | string | When the request object refers to a pod, the procMount types for all containers (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                              |
| `ka.req.role.rules`                                | string | When the request object refers to a role/cluster role, the rules associated with the role                                                                                                                                               |
| `ka.req.role.rules.apiGroups`                      | string | When the request object refers to a role/cluster role, the api groups associated with the role's rules (IDX_ALLOWED, IDX_NUMERIC)                                                                                                       |
| `ka.req.role.rules.nonResourceURLs`                | string | When the request object refers to a role/cluster role, the non resource urls associated with the role's rules (IDX_ALLOWED, IDX_NUMERIC)                                                                                                |
| `ka.req.role.rules.verbs`                          | string | When the request object refers to a role/cluster role, the verbs associated with the role's rules (IDX_ALLOWED, IDX_NUMERIC)                                                                                                            |
| `ka.req.role.rules.resources`                      | string | When the request object refers to a role/cluster role, the resources associated with the role's rules (IDX_ALLOWED, IDX_NUMERIC)                                                                                                        |
| `ka.req.pod.fs_group`                              | string | When the request object refers to a pod, the fsGroup gid specified by the security context.                                                                                                                                             |
| `ka.req.pod.supplemental_groups`                   | string | When the request object refers to a pod, the supplementalGroup gids specified by the security context.                                                                                                                                  |
| `ka.req.pod.containers.add_capabilities`           | string | When the request object refers to a pod, all capabilities to add when running the container. (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                 |
| `ka.req.service.type`                              | string | When the request object refers to a service, the service type                                                                                                                                                                           |
| `ka.req.service.ports`                             | string | When the request object refers to a service, the service's ports (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                                             |
| `ka.req.pod.volumes.hostpath`                      | string | When the request object refers to a pod, all hostPath paths specified for all volumes (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                        |
| `ka.req.volume.hostpath`                           | string | Deprecated by ka.req.pod.volumes.hostpath. Return true if the provided (host) path prefix is used by any volume (IDX_ALLOWED, IDX_KEY)                                                                                                  |
| `ka.req.pod.volumes.flexvolume_driver`             | string | When the request object refers to a pod, all flexvolume drivers specified for all volumes (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                    |
| `ka.req.pod.volumes.volume_type`                   | string | When the request object refers to a pod, all volume types for all volumes (IDX_ALLOWED, IDX_NUMERIC)                                                                                                                                    |
| `ka.resp.name`                                     | string | The response object name                                                                                                                                                                                                                |
| `ka.response.code`                                 | uint64 | The response code                                                                                                                                                                                                                       |
| `ka.response.reason`                               | string | The response reason (usually present only for failures)                                                                                                                                                                                 |
| `ka.useragent`                                     | string | The useragent of the client who made the request to the apiserver                                                                                                                                                                       |

# Development
## Requirements

You need:
* `Go` >= 1.17

## Build

```shell
make
```

# Settings

Only `open_params` accepts settings:
* `cluster`: name of your EKS cluster
* `region`: region of your EKS cluster

# Authentication to AWS

For authentication to AWS API, you can, either:
* export `AWS_ACCESS_KEY_ID` and `AWS_SECRET_KEY`
* set up `.aws/credentials`
* use EC2 Instance Profile

# Configuration files

* `falco.yaml`

  ```yaml
  plugins:
    - name: k8s-audit-logs-eks
      library_path: /usr/share/falco/plugins/libk8s-audit-logs-eks.so
      init_config: ''
      open_params: '{"cluster": "eks-cluster", "region": "eu-west-1"}'
    - name: json
      library_path: /usr/share/falco/plugins/libjson.so
      init_config: ''
      open_params: ''
  load_plugins: [k8s-audit-logs-eks,json]
  ```
  > `open_params` can also be set in `yaml` format:
  > ```yaml
  > open_params:
  >   cluster: "eks-cluster"
  >   region: "eu-west-1"
  > ```

* `k8s-audit-logs-eks-rules.yaml`

The `source` for rules must be `k8s_audit_eks`.

See example:
```yaml
- rule: Disallowed K8s User
  desc: Detect any k8s operation by users outside of an allowed set of users.
  condition: kevt and non_system_user and not ka.user.name in (allowed_k8s_users)
  output: K8s Operation performed by user not in allowed list of users (user=%ka.user.name target=%ka.target.name/%ka.target.resource verb=%ka.verb uri=%ka.uri resp=%ka.response.code)
  priority: WARNING
  source: k8s_audit_eks
  tags: [k8s]
```

# Usage

```shell
falco -c falco.yaml -r k8s-audit-logs-eks-rules.yaml
```

## Requirements

* `Falco` >= 0.31

## Results

```shell
01:27:17.876865758: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=update uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)
01:27:17.876866097: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=get uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)
01:27:17.876869772: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=get uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)
01:27:17.876869773: Warning K8s Operation performed by user not in allowed list of users (user=eks:certificate-controller target=eks-certificates-controller/configmaps verb=update uri=/api/v1/namespaces/kube-system/configmaps/eks-certificates-controller resp=200)

Events detected: 25
Rule counts by severity:
   WARNING: 25
Triggered rules by rule name:
   Disallowed K8s User: 25
Syscall event drop monitoring:
   - event drop detected: 0 occurrences
   - num times actions taken: 0
```