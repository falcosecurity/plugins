# Kubernetes Audit Events Plugin for EKS

## Introduction

This plugin extends Falco to support [Kubernetes Audit Events](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-backends) from AWS EKS clusters as a new data source.
For more details about what Audit logs are, see the [README of k8saudit plugin](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/README.md).

### Functionality

This plugin supports consuming Kubernetes Audit Events stored in Cloudwatch Logs for the EKS Clusters, see [AWS official documentation](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html) for details.

## Capabilities

The `k8saudit-eks` uses the field extraction methods of the [`k8saudit`](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit) plugin as the format for the Audit Logs is same.

### Event Source

The event source for Kubernetes Audit Events from EKS is `k8s_audit`, it allows to use same rules than `k8saudit` plugin.

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
| `ka.validations.admission.policy.failure`          | `string`        | None          | The validation failure reason from a Validation Admission Policy                                                                                                                                             |
| `ka.security.pod.violations`                       | `string`        | None          | The violation reason for pod security policy                                                                                                                                                                 |
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
| `ka.req.binding.subjects.user_names`               | `string (list)` | None          | When the request object refers to a cluster role binding, the subject user names being linked by the binding                                                                                                 |
| `ka.req.binding.subjects.serviceaccount_names`     | `string (list)` | None          | When the request object refers to a cluster role binding, the subject service account names being linked by the binding                                                                                      |
| `ka.req.binding.subjects.serviceaccount_ns_names`  | `string (list)` | None          | When the request object refers to a cluster role binding, the subject serviceaccount namespaced names being linked by the binding, e.g. a list containing: mynamespace:myserviceaccount                      |
| `ka.req.binding.subjects.group_names`              | `string (list)` | None          | When the request object refers to a cluster role binding, the subject group names being linked by the binding                                                                                                |
| `ka.req.binding.role`                              | `string`        | None          | When the request object refers to a cluster role binding, the role being linked by the binding                                                                                                               |
| `ka.req.binding.subject.has_name`                  | `string`        | Key, Required | Deprecated, always returns "N/A". Only provided for backwards compatibility                                                                                                                                  |
| `ka.req.configmap.name`                            | `string`        | None          | If the request object refers to a configmap, the configmap name                                                                                                                                              |
| `ka.req.configmap.obj`                             | `string`        | None          | If the request object refers to a configmap, the entire configmap object                                                                                                                                     |
| `ka.req.pod.containers.args`                       | `string (list)` | Index         | When the request object refers to a pod, the container's args.                                                                                                                                               |
| `ka.req.pod.containers.command`                    | `string (list)` | Index         | When the request object refers to a pod, the container's command.                                                                                                                                            |
| `ka.req.pod.containers.name`                       | `string (list)` | Index         | When the request object refers to a pod, the container's names.                                                                                                                                              |
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

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: k8saudit-eks
    library_path: libk8saudit-eks.so
    init_config:
      region: "us-east-1"
      profile: "default"
      shift: 10
      polling_interval: 10
      use_async: false
      buffer_size: 500
    open_params: "my-cluster"
  - name: json
    library_path: libjson.so
    init_config: ""

load_plugins: [k8saudit-eks, json]
```

**Initialization Config**:
 * `profile`: The Profile to use to create the session, env var `AWS_PROFILE` if present
 * `region`: The Region of your EKS cluster, env var `AWS_REGION` is used if present
 * `use_async`: If true then async extraction optimization is enabled (Default: true)
 * `polling_interval`: Polling Interval in seconds (default: 5s)
 * `shift`: Time shift in past in seconds (default: 1s)
 * `buffer_size`: Buffer Size (default: 200)

**Open Parameters**
A string which contains the name of your EKS Cluster (required).

### Rules

The `k8saudit-eks` plugin ships with no default rule for test purpose, you can use the same rules than those for `k8saudit` plugin. See [here](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml).


To test if it works anyway, you can still use this one for example:

```yaml
- required_engine_version: 15
- required_plugin_versions:
  - name: k8saudit-eks
    version: 0.2.0

- rule: Dummy rule
  desc: >
    Dummy rule
  condition: >
    ka.verb in (get,create,delete,update)
  output: user=%ka.user.name verb=%ka.verb target=%ka.target.name target.namespace=%ka.target.namespace resource=%ka.target.resource
  priority: WARNING
  source: k8s_audit
  tags: [k8s]
```

### AWS IAM Policy Permissions

This plugin retrieves Kubernetes audit events from Amazon CloudWatch Logs and it therefore needs appropriate permissions to perform these actions. If you use a `profile` or associate a role to the service account in Kubernetes with an OIDC provider, you need to grant it permissions.

Here is a AWS IAM policy document that satisfies the requirements:

```json
{
  "Version":"2012-10-17",
  "Statement":[
    {
      "Sid":"ReadAccessToCloudWatchLogs",
      "Effect":"Allow",
      "Action":[
        "logs:Describe*",
        "logs:FilterLogEvents",
        "logs:Get*",
        "logs:List*"
      ],
      "Resource":[
        "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:/aws/eks/${CLUSTER_NAME}/cluster:*"
      ]
    }
  ]
}
```

> **Note**
The three placeholders REGION, ACCOUNT_ID, and CLUSTER_NAME which must be replaced with fitting values.

### Running locally

This plugin requires Falco with version >= **0.35.0**.
```shell
falco -c falco.yaml -r rules/k8s_audit_rules.yaml
```
```shell
17:48:41.067076000: Warning user=eks:certificate-controller verb=get target=eks-certificates-controller target.namespace=kube-system resource=configmapsEvents detected: 1
Rule counts by severity:
   WARNING: 1
Triggered rules by rule name:
   Dummy rule: 1
Syscall event drop monitoring:
   - event drop detected: 0 occurrences
   - num times actions taken: 0
```

### Running in EKS

> **Warning**
When running Falco with the `k8saudit-eks` plugin in a kubernetes cluster, you can't have more than 1 pod at once. The plugin pulls the logs from Cloudwatch Logs, having multiple instances will lead to multiple gatherings of the same logs and the duplication of alerts.

You can use the official [Falco helm chart](https://github.com/falcosecurity/charts/tree/master/falco) to deploy it with the `k8saudit-eks` plugin as 1 replica deployment. You can also use it to associate the IAM role you created (see [AWS IAM Policy Permissions](#aws-iam-policy-permissions)).

See this example of `values.yaml`.

```yaml
tty: true
kubernetes: false #disable the collection of k8s metadata

falco:
  rules_file:
    - /etc/falco/k8s_audit_rules.yaml #rules to use
    - /etc/falco/rules.d
  plugins:
    - name: k8saudit-eks
      library_path: libk8saudit-eks.so
      init_config:
        region: ${REGION} #replace with your region
        shift: 10
        polling_interval: 10
        use_async: false
        buffer_size: 500
      open_params: ${CLUSTER_NAME} #replace with your cluster name
    - name: json
      library_path: libjson.so
      init_config: ""
  load_plugins: [k8saudit-eks, json] #plugins to load

driver:
  enabled: false #disable the collection of syscalls
collectors:
  enabled: false #disable the collection of container metadata

controller:
  kind: deployment
  deployment:
    replicas: 1 #1 replica deployment to avoid duplication of alerts

falcoctl: #use falcoctl to install automatically the plugin and the rules
  indexes:
  - name: falcosecurity
    url: https://falcosecurity.github.io/falcoctl/index.yaml
  artifact:
    install:
      enabled: true
    follow:
      enabled: true
  config:
    artifact:
      allowedTypes:
        - plugin
        - rulesfile
      install:
        resolveDeps: false
        refs: [k8saudit-rules:0, k8saudit-eks:0, json:0]
      follow:
        refs: [k8saudit-rules:0]

serviceAccount:
  create: true
  annotations:
    - eks.amazonaws.com/role-arn: arn:aws:iam::${ACCOUNT_ID}:role/${ROLE} #if you use an OIDC provider, you can attach a role to the service account
```

> **Note**
Note the three placeholders REGION, ACCOUNT_ID, and CLUSTER_NAME which must be replaced with fitting values.

### Warning

> **Warning**
AWS Cloudwatch Logs truncates log lines with more than 10,000 characters, as these lines can't be parsed by the plugin they are ignored and some events may be missed.
