# Kubernetes Audit Events Plugin for AKS

## Introduction

This plugin extends Falco to support [Kubernetes Audit Events](https://kubernetes.io/docs/tasks/debug-application-cluster/audit/#audit-backends) from AKS clusters as a new data source.
For more details about what Audit logs are, see the [README of k8saudit plugin](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/README.md).

### Functionality

This plugin supports consuming Kubernetes Audit Events stored in Azure Event Hub for the AKS Clusters, see [Azure official documentation](https://learn.microsoft.com/en-us/azure/aks/monitor-aks#aks-control-planeresource-logs) for details.

It can read the Event Hub over either of its two protocols:
* **AMQP** (default): the native Event Hubs SDK, checkpointing progress to a Blob Storage container.
* **Kafka**: the [Kafka-compatible endpoint](https://learn.microsoft.com/en-us/azure/event-hubs/azure-event-hubs-kafka-overview) Event Hubs exposes on port 9093. Event Hubs tracks Kafka consumer-group offsets itself, so no Blob Storage container is needed with this protocol.

Both protocols support the same four authentication mechanisms: a shared access key connection string (the default), or an Azure AD (Microsoft Entra ID) credential — environment (client secret or certificate), managed identity (system- or user-assigned), or workload identity.

## Capabilities

The `k8saudit-aks` uses the field extraction methods of the [`k8saudit`](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit) plugin as the format for the Audit Logs is same.

### Event Source

The event source for Kubernetes Audit Events from AKS is `k8s_audit`, it allows to use same rules than `k8saudit` plugin.

### Supported Fields

Here is the current set of supported fields (from `k8saudit` plugin's extractor):

<!-- README-PLUGIN-FIELDS -->
|                            NAME                             |      TYPE       |      ARG      |                                                                                                       DESCRIPTION                                                                                                       |
|-------------------------------------------------------------|-----------------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ka.auditid`                                                | `string`        | None          | The unique id of the audit event                                                                                                                                                                                        |
| `ka.stage`                                                  | `string`        | None          | Stage of the request (e.g. RequestReceived, ResponseComplete, etc.)                                                                                                                                                     |
| `ka.auth.decision`                                          | `string`        | None          | The authorization decision                                                                                                                                                                                              |
| `ka.auth.reason`                                            | `string`        | None          | The authorization reason                                                                                                                                                                                                |
| `ka.auth.openshift.decision`                                | `string`        | None          | The authentication decision of the openshfit apiserver extention. Only available on openshift clusters                                                                                                                  |
| `ka.validations.admission.policy.failure`                   | `string`        | None          | The validation failure reason from a Validation Admission Policy                                                                                                                                                        |
| `ka.security.pod.violations`                                | `string`        | None          | The violation reason for pod security policy                                                                                                                                                                            |
| `ka.auth.openshift.username`                                | `string`        | None          | The user name performing the openshift authentication operation. Only available on openshift clusters                                                                                                                   |
| `ka.user.name`                                              | `string`        | None          | The user name performing the request                                                                                                                                                                                    |
| `ka.user.groups`                                            | `string (list)` | None          | The groups to which the user belongs                                                                                                                                                                                    |
| `ka.impuser.name`                                           | `string`        | None          | The impersonated user name                                                                                                                                                                                              |
| `ka.verb`                                                   | `string`        | None          | The action being performed                                                                                                                                                                                              |
| `ka.uri`                                                    | `string`        | None          | The request URI as sent from client to server                                                                                                                                                                           |
| `ka.uri.param`                                              | `string`        | Key, Required | The value of a given query parameter in the uri (e.g. when uri=/foo?key=val, ka.uri.param[key] is val).                                                                                                                 |
| `ka.target.name`                                            | `string`        | None          | The target object name                                                                                                                                                                                                  |
| `ka.target.namespace`                                       | `string`        | None          | The target object namespace                                                                                                                                                                                             |
| `ka.target.resource`                                        | `string`        | None          | The target object resource                                                                                                                                                                                              |
| `ka.target.subresource`                                     | `string`        | None          | The target object subresource                                                                                                                                                                                           |
| `ka.target.pod.name`                                        | `string`        | None          | The target pod name                                                                                                                                                                                                     |
| `ka.req.binding.subjects`                                   | `string (list)` | None          | When the request object refers to a cluster role binding, the subject (e.g. account/users) being linked by the binding                                                                                                  |
| `ka.req.binding.subjects.user_names`                        | `string (list)` | None          | When the request object refers to a cluster role binding, the subject user names being linked by the binding                                                                                                            |
| `ka.req.binding.subjects.serviceaccount_names`              | `string (list)` | None          | When the request object refers to a cluster role binding, the subject service account names being linked by the binding                                                                                                 |
| `ka.req.binding.subjects.serviceaccount_ns_names`           | `string (list)` | None          | When the request object refers to a cluster role binding, the subject serviceaccount namespaced names being linked by the binding, e.g. a list containing: mynamespace:myserviceaccount                                 |
| `ka.req.binding.subjects.group_names`                       | `string (list)` | None          | When the request object refers to a cluster role binding, the subject group names being linked by the binding                                                                                                           |
| `ka.req.binding.role`                                       | `string`        | None          | When the request object refers to a cluster role binding, the role being linked by the binding                                                                                                                          |
| `ka.req.binding.subject.has_name`                           | `string`        | Key, Required | Deprecated, always returns "N/A". Only provided for backwards compatibility                                                                                                                                             |
| `ka.req.configmap.name`                                     | `string`        | None          | If the request object refers to a configmap, the configmap name                                                                                                                                                         |
| `ka.req.configmap.obj`                                      | `string`        | None          | If the request object refers to a configmap, the entire configmap object                                                                                                                                                |
| `ka.req.pod.containers.args`                                | `string (list)` | Index         | When the request object refers to a pod, the container's args.                                                                                                                                                          |
| `ka.req.pod.containers.command`                             | `string (list)` | Index         | When the request object refers to a pod, the container's command.                                                                                                                                                       |
| `ka.req.pod.containers.name`                                | `string (list)` | Index         | When the request object refers to a pod, the container's names.                                                                                                                                                         |
| `ka.req.pod.containers.image`                               | `string (list)` | Index         | When the request object refers to a pod, the container's images.                                                                                                                                                        |
| `ka.req.container.image`                                    | `string`        | None          | Deprecated by ka.req.pod.containers.image. Returns the image of the first container only                                                                                                                                |
| `ka.req.pod.containers.image.repository`                    | `string (list)` | Index         | The same as req.container.image, but only the repository part (e.g. falcosecurity/falco).                                                                                                                               |
| `ka.req.container.image.repository`                         | `string`        | None          | Deprecated by ka.req.pod.containers.image.repository. Returns the repository of the first container only                                                                                                                |
| `ka.req.pod.host_ipc`                                       | `string`        | None          | When the request object refers to a pod, the value of the hostIPC flag.                                                                                                                                                 |
| `ka.req.pod.host_network`                                   | `string`        | None          | When the request object refers to a pod, the value of the hostNetwork flag.                                                                                                                                             |
| `ka.req.container.host_network`                             | `string`        | None          | Deprecated alias for ka.req.pod.host_network                                                                                                                                                                            |
| `ka.req.pod.host_pid`                                       | `string`        | None          | When the request object refers to a pod, the value of the hostPID flag.                                                                                                                                                 |
| `ka.req.pod.containers.host_port`                           | `string (list)` | Index         | When the request object refers to a pod, all container's hostPort values.                                                                                                                                               |
| `ka.req.pod.containers.privileged`                          | `string (list)` | Index         | When the request object refers to a pod, the value of the privileged flag for all containers.                                                                                                                           |
| `ka.req.container.privileged`                               | `string`        | None          | Deprecated by ka.req.pod.containers.privileged. Returns true if any container has privileged=true                                                                                                                       |
| `ka.req.pod.containers.allow_privilege_escalation`          | `string (list)` | Index         | When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all containers                                                                                                              |
| `ka.req.pod.containers.read_only_fs`                        | `string (list)` | Index         | When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all containers                                                                                                                |
| `ka.req.pod.run_as_user`                                    | `string`        | None          | When the request object refers to a pod, the runAsUser uid specified in the security context for the pod. See ....containers.run_as_user for the runAsUser for individual containers                                    |
| `ka.req.pod.containers.run_as_user`                         | `string (list)` | Index         | When the request object refers to a pod, the runAsUser uid for all containers                                                                                                                                           |
| `ka.req.pod.containers.eff_run_as_user`                     | `string (list)` | Index         | When the request object refers to a pod, the initial uid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified            |
| `ka.req.pod.run_as_group`                                   | `string`        | None          | When the request object refers to a pod, the runAsGroup gid specified in the security context for the pod. See ....containers.run_as_group for the runAsGroup for individual containers                                 |
| `ka.req.pod.containers.run_as_group`                        | `string (list)` | Index         | When the request object refers to a pod, the runAsGroup gid for all containers                                                                                                                                          |
| `ka.req.pod.containers.eff_run_as_group`                    | `string (list)` | Index         | When the request object refers to a pod, the initial gid that will be used for all containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified            |
| `ka.req.pod.containers.proc_mount`                          | `string (list)` | Index         | When the request object refers to a pod, the procMount types for all containers                                                                                                                                         |
| `ka.req.role.rules`                                         | `string (list)` | None          | When the request object refers to a role/cluster role, the rules associated with the role                                                                                                                               |
| `ka.req.role.rules.apiGroups`                               | `string (list)` | Index         | When the request object refers to a role/cluster role, the api groups associated with the role's rules                                                                                                                  |
| `ka.req.role.rules.nonResourceURLs`                         | `string (list)` | Index         | When the request object refers to a role/cluster role, the non resource urls associated with the role's rules                                                                                                           |
| `ka.req.role.rules.verbs`                                   | `string (list)` | Index         | When the request object refers to a role/cluster role, the verbs associated with the role's rules                                                                                                                       |
| `ka.req.role.rules.resources`                               | `string (list)` | Index         | When the request object refers to a role/cluster role, the resources associated with the role's rules                                                                                                                   |
| `ka.req.pod.fs_group`                                       | `string`        | None          | When the request object refers to a pod, the fsGroup gid specified by the security context.                                                                                                                             |
| `ka.req.pod.supplemental_groups`                            | `string (list)` | None          | When the request object refers to a pod, the supplementalGroup gids specified by the security context.                                                                                                                  |
| `ka.req.pod.containers.add_capabilities`                    | `string (list)` | Index         | When the request object refers to a pod, all capabilities to add when running the container.                                                                                                                            |
| `ka.req.service.type`                                       | `string`        | None          | When the request object refers to a service, the service type                                                                                                                                                           |
| `ka.req.service.ports`                                      | `string (list)` | Index         | When the request object refers to a service, the service's ports                                                                                                                                                        |
| `ka.req.pod.volumes.hostpath`                               | `string (list)` | Index         | When the request object refers to a pod, all hostPath paths specified for all volumes                                                                                                                                   |
| `ka.req.volume.hostpath`                                    | `string`        | Key, Required | Deprecated by ka.req.pod.volumes.hostpath. Return true if the provided (host) path prefix is used by any volume                                                                                                         |
| `ka.req.pod.volumes.flexvolume_driver`                      | `string (list)` | Index         | When the request object refers to a pod, all flexvolume drivers specified for all volumes                                                                                                                               |
| `ka.req.pod.volumes.volume_type`                            | `string (list)` | Index         | When the request object refers to a pod, all volume types for all volumes                                                                                                                                               |
| `ka.resp.name`                                              | `string`        | None          | The response object name                                                                                                                                                                                                |
| `ka.response.code`                                          | `string`        | None          | The response code                                                                                                                                                                                                       |
| `ka.response.reason`                                        | `string`        | None          | The response reason (usually present only for failures)                                                                                                                                                                 |
| `ka.useragent`                                              | `string`        | None          | The useragent of the client who made the request to the apiserver                                                                                                                                                       |
| `ka.sourceips`                                              | `string (list)` | Index         | The IP addresses of the client who made the request to the apiserver                                                                                                                                                    |
| `ka.cluster.name`                                           | `string`        | None          | The name of the k8s cluster                                                                                                                                                                                             |
| `ka.req.pod.initContainers.name`                            | `string (list)` | Index         | When the request object refers to a pod, the init containers names.                                                                                                                                                     |
| `ka.req.pod.initContainers.image`                           | `string (list)` | Index         | When the request object refers to a pod, the init containers images.                                                                                                                                                    |
| `ka.req.pod.initContainers.image.repository`                | `string (list)` | Index         | The same as ka.req.pod.initContainers.image, but only the repository part (e.g. falcosecurity/falco).                                                                                                                   |
| `ka.req.pod.initContainers.command`                         | `string (list)` | Index         | When the request object refers to a pod, the init containers commands.                                                                                                                                                  |
| `ka.req.pod.initContainers.args`                            | `string (list)` | Index         | When the request object refers to a pod, the init containers args.                                                                                                                                                      |
| `ka.req.pod.initContainers.privileged`                      | `string (list)` | Index         | When the request object refers to a pod, the value of the privileged flag for all init containers.                                                                                                                      |
| `ka.req.pod.initContainers.allow_privilege_escalation`      | `string (list)` | Index         | When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all init containers.                                                                                                        |
| `ka.req.pod.initContainers.read_only_fs`                    | `string (list)` | Index         | When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all init containers.                                                                                                          |
| `ka.req.pod.initContainers.run_as_user`                     | `string (list)` | Index         | When the request object refers to a pod, the runAsUser uid for all init containers.                                                                                                                                     |
| `ka.req.pod.initContainers.eff_run_as_user`                 | `string (list)` | Index         | When the request object refers to a pod, the initial uid that will be used for all init containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified.      |
| `ka.req.pod.initContainers.run_as_group`                    | `string (list)` | Index         | When the request object refers to a pod, the runAsGroup gid for all init containers.                                                                                                                                    |
| `ka.req.pod.initContainers.eff_run_as_group`                | `string (list)` | Index         | When the request object refers to a pod, the initial gid that will be used for all init containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified.      |
| `ka.req.pod.initContainers.proc_mount`                      | `string (list)` | Index         | When the request object refers to a pod, the procMount type for all init containers.                                                                                                                                    |
| `ka.req.pod.initContainers.add_capabilities`                | `string (list)` | Index         | When the request object refers to a pod, the capabilities added for all init containers.                                                                                                                                |
| `ka.req.pod.initContainers.host_port`                       | `string (list)` | Index         | When the request object refers to a pod, all init containers hostPort values.                                                                                                                                           |
| `ka.req.pod.ephemeralContainers.name`                       | `string (list)` | Index         | When the request object refers to a pod, the ephemeral containers names.                                                                                                                                                |
| `ka.req.pod.ephemeralContainers.image`                      | `string (list)` | Index         | When the request object refers to a pod, the ephemeral containers images.                                                                                                                                               |
| `ka.req.pod.ephemeralContainers.image.repository`           | `string (list)` | Index         | The same as ka.req.pod.ephemeralContainers.image, but only the repository part (e.g. falcosecurity/falco).                                                                                                              |
| `ka.req.pod.ephemeralContainers.command`                    | `string (list)` | Index         | When the request object refers to a pod, the ephemeral containers commands.                                                                                                                                             |
| `ka.req.pod.ephemeralContainers.args`                       | `string (list)` | Index         | When the request object refers to a pod, the ephemeral containers args.                                                                                                                                                 |
| `ka.req.pod.ephemeralContainers.privileged`                 | `string (list)` | Index         | When the request object refers to a pod, the value of the privileged flag for all ephemeral containers.                                                                                                                 |
| `ka.req.pod.ephemeralContainers.allow_privilege_escalation` | `string (list)` | Index         | When the request object refers to a pod, the value of the allowPrivilegeEscalation flag for all ephemeral containers.                                                                                                   |
| `ka.req.pod.ephemeralContainers.read_only_fs`               | `string (list)` | Index         | When the request object refers to a pod, the value of the readOnlyRootFilesystem flag for all ephemeral containers.                                                                                                     |
| `ka.req.pod.ephemeralContainers.run_as_user`                | `string (list)` | Index         | When the request object refers to a pod, the runAsUser uid for all ephemeral containers.                                                                                                                                |
| `ka.req.pod.ephemeralContainers.eff_run_as_user`            | `string (list)` | Index         | When the request object refers to a pod, the initial uid that will be used for all ephemeral containers. This combines information from both the pod and container security contexts and uses 0 if no uid is specified. |
| `ka.req.pod.ephemeralContainers.run_as_group`               | `string (list)` | Index         | When the request object refers to a pod, the runAsGroup gid for all ephemeral containers.                                                                                                                               |
| `ka.req.pod.ephemeralContainers.eff_run_as_group`           | `string (list)` | Index         | When the request object refers to a pod, the initial gid that will be used for all ephemeral containers. This combines information from both the pod and container security contexts and uses 0 if no gid is specified. |
| `ka.req.pod.ephemeralContainers.proc_mount`                 | `string (list)` | Index         | When the request object refers to a pod, the procMount type for all ephemeral containers.                                                                                                                               |
| `ka.req.pod.ephemeralContainers.add_capabilities`           | `string (list)` | Index         | When the request object refers to a pod, the capabilities added for all ephemeral containers.                                                                                                                           |
<!-- /README-PLUGIN-FIELDS -->

## Usage

### Configuration

The plugin reads events over one of two protocols (`protocol`), authenticating with one of four mechanisms (`auth.type`) — every combination of the two is supported. `environment` and `managed_identity` each cover two variants (client secret vs. client certificate; system-assigned vs. user-assigned), for six auth variants in total:

| | `amqp` | `kafka` |
|---|---|---|
| `connection_string` (default) | [example](#amqp-protocol--connection-string-default) | [example](#kafka-protocol--connection-string) |
| `environment` — client secret | [example](#amqp-protocol--environment-credential-client-secret) | [example](#kafka-protocol--environment-credential-client-secret) |
| `environment` — client certificate | [example](#amqp-protocol--environment-credential-client-certificate) | [example](#kafka-protocol--environment-credential-client-certificate) |
| `managed_identity` — system-assigned | [example](#amqp-protocol--system-assigned-managed-identity) | [example](#kafka-protocol--system-assigned-managed-identity) |
| `managed_identity` — user-assigned | [example](#amqp-protocol--user-assigned-managed-identity) | [example](#kafka-protocol--user-assigned-managed-identity) |
| `workload_identity` | [example](#amqp-protocol--workload-identity) | [example](#kafka-protocol--workload-identity) |

**Initialization Config**:
* `protocol` (optional, default `amqp`): The transport used to read events from Event Hub, `amqp` or `kafka`
* `auth.type` (optional, default `connection_string`): The auth mechanism, one of `connection_string`, `environment`, `managed_identity`, `workload_identity`. `workload_identity` is always sourced from the environment (`AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_FEDERATED_TOKEN_FILE`, as injected by the AKS workload identity webhook) and has no `init_config` fields of its own
* `auth.managed_identity_client_id` (optional): Client ID of a user-assigned managed identity. Only used when `auth.type` is `managed_identity`; leave empty for the system-assigned identity. Falls back to the `AZURE_CLIENT_ID` environment variable
* `auth.tenant_id`, `auth.client_id`, `auth.client_secret`, `auth.client_certificate_path`, `auth.client_certificate_password`, `auth.client_send_certificate_chain` (optional): Service principal credentials used when `auth.type` is `environment`. `tenant_id` and `client_id` are always required (here or via `AZURE_TENANT_ID` / `AZURE_CLIENT_ID`); set either `client_secret` (or `AZURE_CLIENT_SECRET`) for a client-secret service principal, or `client_certificate_path` (or `AZURE_CLIENT_CERTIFICATE_PATH`) for a client-certificate one. For the certificate case, `client_certificate_password` (or `AZURE_CLIENT_CERTIFICATE_PASSWORD`) is optional and only needed if the certificate's private key is encrypted, and `client_send_certificate_chain` (or `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`, `"1"`/`"true"`) is an optional boolean, default `false`, that sends the certificate chain for Subject Name/Issuer (SNI) authentication. Any of these left empty in `init_config` is read from the matching environment variable instead, so credentials can come from config, environment, or a mix of both
* `event_hub_namespace_connection_string` (required when `auth.type` is `connection_string`): The connection string of the EventHub Namespace to read from
* `event_hub_namespace` (required for `protocol: kafka`, and for any `auth.type` other than `connection_string`): The fully qualified EventHub namespace, e.g. `my-namespace.servicebus.windows.net`. With `protocol: kafka` and `auth.type: connection_string` it can be left empty — it's derived from `event_hub_namespace_connection_string`
* `event_hub_name` (required): The name of the EventHub to read from
* `consumer_group` (optional, default `$Default`): The EventHub consumer group (`amqp`) or Kafka consumer group id (`kafka`)
* `blob_storage_connection_string` (required for `protocol: amqp` with `auth.type: connection_string`): The connection string of the Blob Storage to use as checkpoint store
* `blob_storage_account_url` (required for `protocol: amqp` with a non-`connection_string` `auth.type`): The Blob Storage account URL, e.g. `https://myaccount.blob.core.windows.net`
* `blob_storage_container_name` (required for `protocol: amqp`): The name of the Blob Storage container to use as checkpoint store. Not used by `protocol: kafka` — Event Hubs tracks Kafka consumer-group offsets itself
* `rate_limit_events_per_second` (optional): The rate limit of events per second to read from EventHub
* `rate_limit_burst` (optional): The rate limit burst of events to read from EventHub

A non-`connection_string` `auth.type` requires the identity (service principal, managed identity, or federated workload identity) to have:
* the **Azure Event Hubs Data Receiver** role on the Event Hub namespace (or the specific hub)
* for `protocol: amqp`, the **Storage Blob Data Contributor** role on the Blob Storage checkpoint container

#### AMQP protocol — connection string (default)

This is the default configuration, unchanged from before `protocol` and `auth` existed — any existing `init_config` that only sets the fields below keeps working as-is:

```yaml
plugins:
  - name: k8saudit-aks
    library_path: libk8saudit-aks.so
    init_config:
      event_hub_namespace_connection_string: "xxxx"
      event_hub_name: "<my-hub>"
      blob_storage_connection_string: "xxxxx"
      blob_storage_container_name: "<container-name>"
      rate_limit_events_per_second: 100
      rate_limit_burst: 200
    open_params: "my-cluster"
  - name: json
    library_path: libjson.so
    init_config: ""

load_plugins: [k8saudit-aks, json]
```

#### AMQP protocol — environment credential (client secret)

Either put the service principal's credentials in `init_config`:

```yaml
init_config:
  protocol: amqp
  auth:
    type: environment
    tenant_id: "<tenant-id>"
    client_id: "<client-id>"
    client_secret: "<client-secret>"
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
  blob_storage_account_url: "https://mystorage.blob.core.windows.net"
  blob_storage_container_name: "<container-name>"
```

or leave `auth` empty besides `type` and set `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` on the Falco process/container — any field left out of `init_config` is read from its environment variable. The two can also be mixed, e.g. `client_id` in config with `AZURE_CLIENT_SECRET` from the environment.

#### AMQP protocol — environment credential (client certificate)

```yaml
init_config:
  protocol: amqp
  auth:
    type: environment
    tenant_id: "<tenant-id>"
    client_id: "<client-id>"
    client_certificate_path: "/etc/falco/azure-client-cert.pem"
    client_certificate_password: "<certificate-password>"       # optional, only if the key is encrypted
    client_send_certificate_chain: true                          # optional, only for SNI authentication; default false
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
  blob_storage_account_url: "https://mystorage.blob.core.windows.net"
  blob_storage_container_name: "<container-name>"
```

or, equivalently, set `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_CERTIFICATE_PATH` on the Falco process/container, plus optionally `AZURE_CLIENT_CERTIFICATE_PASSWORD` and/or `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`.

#### AMQP protocol — system-assigned managed identity

```yaml
init_config:
  protocol: amqp
  auth:
    type: managed_identity
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
  blob_storage_account_url: "https://mystorage.blob.core.windows.net"
  blob_storage_container_name: "<container-name>"
```

#### AMQP protocol — user-assigned managed identity

```yaml
init_config:
  protocol: amqp
  auth:
    type: managed_identity
    managed_identity_client_id: "11111111-1111-1111-1111-111111111111"
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
  blob_storage_account_url: "https://mystorage.blob.core.windows.net"
  blob_storage_container_name: "<container-name>"
```

#### AMQP protocol — workload identity

For a Falco pod running in AKS with [workload identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview) configured (the AKS webhook injects `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE` automatically). There is no config equivalent — workload identity is always sourced from the environment:

```yaml
init_config:
  protocol: amqp
  auth:
    type: workload_identity
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
  blob_storage_account_url: "https://mystorage.blob.core.windows.net"
  blob_storage_container_name: "<container-name>"
```

#### Kafka protocol — connection string

```yaml
init_config:
  protocol: kafka
  event_hub_namespace_connection_string: "xxxx"
  event_hub_name: "<my-hub>"
```

#### Kafka protocol — environment credential (client secret)

```yaml
init_config:
  protocol: kafka
  auth:
    type: environment
    tenant_id: "<tenant-id>"
    client_id: "<client-id>"
    client_secret: "<client-secret>"
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
```

or leave `auth` empty besides `type` and set `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` on the Falco process/container — any field left out of `init_config` is read from its environment variable. The two can also be mixed, e.g. `client_id` in config with `AZURE_CLIENT_SECRET` from the environment.

#### Kafka protocol — environment credential (client certificate)

```yaml
init_config:
  protocol: kafka
  auth:
    type: environment
    tenant_id: "<tenant-id>"
    client_id: "<client-id>"
    client_certificate_path: "/etc/falco/azure-client-cert.pem"
    client_certificate_password: "<certificate-password>"       # optional, only if the key is encrypted
    client_send_certificate_chain: true                          # optional, only for SNI authentication; default false
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
```

or, equivalently, set `AZURE_TENANT_ID` / `AZURE_CLIENT_ID` / `AZURE_CLIENT_CERTIFICATE_PATH` on the Falco process/container, plus optionally `AZURE_CLIENT_CERTIFICATE_PASSWORD` and/or `AZURE_CLIENT_SEND_CERTIFICATE_CHAIN`.

#### Kafka protocol — system-assigned managed identity

```yaml
init_config:
  protocol: kafka
  auth:
    type: managed_identity
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
```

#### Kafka protocol — user-assigned managed identity

```yaml
init_config:
  protocol: kafka
  auth:
    type: managed_identity
    managed_identity_client_id: "11111111-1111-1111-1111-111111111111"
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
```

#### Kafka protocol — workload identity

For a Falco pod running in AKS with [workload identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview) configured (the AKS webhook injects `AZURE_CLIENT_ID`, `AZURE_TENANT_ID` and `AZURE_FEDERATED_TOKEN_FILE` automatically). There is no config equivalent — workload identity is always sourced from the environment:

```yaml
init_config:
  protocol: kafka
  auth:
    type: workload_identity
  event_hub_namespace: "my-namespace.servicebus.windows.net"
  event_hub_name: "<my-hub>"
```

**Open Parameters**

No open parameters are required for this plugin.

### Rules

The `k8saudit-aks` plugin ships with no default rule for test purpose, you can use the same rules than those for `k8saudit` plugin. See [here](https://github.com/falcosecurity/plugins/blob/main/plugins/k8saudit/rules/k8s_audit_rules.yaml).

To test if it works anyway, you can still use this one for example:

```yaml
- required_engine_version: 15
- required_plugin_versions:
  - name: k8saudit-aks
    version: 0.7.0

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
