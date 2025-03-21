#include <plugin.h>

//////////////////////////
// Extract capability
//////////////////////////

// Keep this aligned with `get_fields`
enum ContainerFields
{
    TYPE_CONTAINER_ID,
    TYPE_CONTAINER_FULL_CONTAINER_ID,
    TYPE_CONTAINER_NAME,
    TYPE_CONTAINER_IMAGE,
    TYPE_CONTAINER_IMAGE_ID,
    TYPE_CONTAINER_TYPE,
    TYPE_CONTAINER_PRIVILEGED,
    TYPE_CONTAINER_MOUNTS,
    TYPE_CONTAINER_MOUNT,
    TYPE_CONTAINER_MOUNT_SOURCE,
    TYPE_CONTAINER_MOUNT_DEST,
    TYPE_CONTAINER_MOUNT_MODE,
    TYPE_CONTAINER_MOUNT_RDWR,
    TYPE_CONTAINER_MOUNT_PROPAGATION,
    TYPE_CONTAINER_IMAGE_REPOSITORY,
    TYPE_CONTAINER_IMAGE_TAG,
    TYPE_CONTAINER_IMAGE_DIGEST,
    TYPE_CONTAINER_HEALTHCHECK,
    TYPE_CONTAINER_LIVENESS_PROBE,
    TYPE_CONTAINER_READINESS_PROBE,
    TYPE_CONTAINER_START_TS,
    TYPE_CONTAINER_DURATION,
    TYPE_CONTAINER_IP_ADDR,
    TYPE_CONTAINER_CNIRESULT,
    TYPE_CONTAINER_HOST_PID,
    TYPE_CONTAINER_HOST_NETWORK,
    TYPE_CONTAINER_HOST_IPC,
    TYPE_CONTAINER_LABEL,
    TYPE_CONTAINER_LABELS,
    TYPE_IS_CONTAINER_HEALTHCHECK,
    TYPE_IS_CONTAINER_LIVENESS_PROBE,
    TYPE_IS_CONTAINER_READINESS_PROBE,
    TYPE_K8S_POD_NAME,
    TYPE_K8S_NS_NAME,
    TYPE_K8S_POD_ID,
    TYPE_K8S_POD_UID,
    TYPE_K8S_POD_SANDBOX_ID,
    TYPE_K8S_POD_FULL_SANDBOX_ID,
    TYPE_K8S_POD_LABEL,
    TYPE_K8S_POD_LABELS,
    TYPE_K8S_POD_IP,
    TYPE_K8S_POD_CNIRESULT,
    // below fields are all deprecated
    TYPE_K8S_RC_NAME,
    TYPE_K8S_RC_ID,
    TYPE_K8S_RC_LABEL,
    TYPE_K8S_RC_LABELS,
    TYPE_K8S_SVC_NAME,
    TYPE_K8S_SVC_ID,
    TYPE_K8S_SVC_LABEL,
    TYPE_K8S_SVC_LABELS,
    TYPE_K8S_NS_ID,
    TYPE_K8S_NS_LABEL,
    TYPE_K8S_NS_LABELS,
    TYPE_K8S_RS_NAME,
    TYPE_K8S_RS_ID,
    TYPE_K8S_RS_LABEL,
    TYPE_K8S_RS_LABELS,
    TYPE_K8S_DEPLOYMENT_NAME,
    TYPE_K8S_DEPLOYMENT_ID,
    TYPE_K8S_DEPLOYMENT_LABEL,
    TYPE_K8S_DEPLOYMENT_LABELS,
    TYPE_CONTAINER_FIELD_MAX
};

std::vector<std::string> my_plugin::get_extract_event_sources()
{
    return EXTRACT_EVENT_SOURCES;
}

std::vector<falcosecurity::field_info> my_plugin::get_fields()
{
    using ft = falcosecurity::field_value_type;

    // Weird cxx20 syntax for designated initializers
    falcosecurity::field_arg req_both_arg;
    req_both_arg.key = true;
    req_both_arg.index = true;
    req_both_arg.required = true;

    falcosecurity::field_arg req_key_arg;
    req_key_arg.key = true;
    req_key_arg.required = true;

    // Use an array to perform a static_assert one the size.
    const falcosecurity::field_info fields[] = {
            {ft::FTYPE_STRING,
             "container.id",
             "Container ID",
             "The truncated container ID (first 12 characters), e.g. "
             "3ad7b26ded6d is extracted from "
             "the Linux cgroups by Falco within the kernel. Consequently, this "
             "field is reliably "
             "available and serves as the lookup key for Falco's synchronous "
             "or asynchronous requests "
             "against the container runtime socket to retrieve all other "
             "'container.*' information. "
             "One important aspect to be aware of is that if the process "
             "occurs on the host, meaning "
             "not in the container PID namespace, this field is set to a "
             "string called 'host'. In "
             "Kubernetes, pod sandbox container processes can exist where "
             "`container.id` matches "
             "`k8s.pod.sandbox_id`, lacking other 'container.*' details.",
             {},
             false,
             {},
             true}, // use as suggested output format
            {ft::FTYPE_STRING, "container.full_id", "Container ID",
             "The full container ID, e.g. "
             "3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e."
             " In contrast to "
             "`container.id`, we enrich this field as part of the container "
             "engine enrichment. In "
             "instances of userspace container engine lookup delays, this "
             "field may not be available "
             "yet."},
            {ft::FTYPE_STRING,
             "container.name",
             "Container Name",
             "The container name. In instances of userspace container engine "
             "lookup delays, this field "
             "may not be available yet. One important aspect to be aware of is "
             "that if the process "
             "occurs on the host, meaning not in the container PID namespace, "
             "this field is set to a "
             "string called 'host'.",
             {},
             false,
             {},
             true}, // use as suggested output format
            {ft::FTYPE_STRING, "container.image", "Image Name",
             "The container image name (e.g. falcosecurity/falco:latest for "
             "docker). In instances of "
             "userspace container engine lookup delays, this field may not be "
             "available yet."},
            {ft::FTYPE_STRING, "container.image.id", "Image ID",
             "The container image id (e.g. 6f7e2741b66b). In instances of "
             "userspace container engine "
             "lookup delays, this field may not be available yet."},
            {ft::FTYPE_STRING, "container.type", "Type",
             "The container type, e.g. docker, cri-o, containerd etc."},
            {ft::FTYPE_BOOL, "container.privileged", "Privileged",
             "'true' for containers running as privileged, 'false' otherwise. "
             "In instances of "
             "userspace container engine lookup delays, this field may not be "
             "available yet."},
            {ft::FTYPE_STRING, "container.mounts", "Mounts",
             "A space-separated list of mount information. Each item in the "
             "list has the format "
             "'source:dest:mode:rdrw:propagation'. In instances of userspace "
             "container engine lookup "
             "delays, this field may not be available yet."},
            {ft::FTYPE_STRING, "container.mount", "Mount",
             "Information about a single mount, specified by number (e.g. "
             "container.mount[0]) or mount "
             "source (container.mount[/usr/local]). The pathname can be a glob "
             "(container.mount[/usr/local/*]), in which case the first "
             "matching mount will be "
             "returned. The information has the format "
             "'source:dest:mode:rdrw:propagation'. If there "
             "is no mount with the specified index or matching the provided "
             "source, returns the string "
             "\"none\" instead of a NULL value. In instances of userspace "
             "container engine lookup "
             "delays, this field may not be available yet.",
             req_both_arg},
            {ft::FTYPE_STRING, "container.mount.source", "Mount Source",
             "The mount source, specified by number (e.g. "
             "container.mount.source[0]) or mount "
             "destination (container.mount.source[/host/lib/modules]). The "
             "pathname can be a glob. In "
             "instances of userspace container engine lookup delays, this "
             "field may not be available "
             "yet.",
             req_both_arg},
            {ft::FTYPE_STRING, "container.mount.dest", "Mount Destination",
             "The mount destination, specified by number (e.g. "
             "container.mount.dest[0]) or mount "
             "source (container.mount.dest[/lib/modules]). The pathname can be "
             "a glob. In instances of "
             "userspace container engine lookup delays, this field may not be "
             "available yet.",
             req_both_arg},
            {ft::FTYPE_STRING, "container.mount.mode", "Mount Mode",
             "The mount mode, specified by number (e.g. "
             "container.mount.mode[0]) or mount source "
             "(container.mount.mode[/usr/local]). The pathname can be a glob. "
             "In instances of "
             "userspace container engine lookup delays, this field may not be "
             "available yet.",
             req_both_arg},
            {ft::FTYPE_STRING, "container.mount.rdwr", "Mount Read/Write",
             "The mount rdwr value, specified by number (e.g. "
             "container.mount.rdwr[0]) or mount source "
             "(container.mount.rdwr[/usr/local]). The pathname can be a glob. "
             "In instances of "
             "userspace container engine lookup delays, this field may not be "
             "available yet.",
             req_both_arg},
            {ft::FTYPE_STRING, "container.mount.propagation",
             "Mount Propagation",
             "The mount propagation value, specified by number (e.g. "
             "container.mount.propagation[0]) "
             "or mount source (container.mount.propagation[/usr/local]). The "
             "pathname can be a glob. "
             "In instances of userspace container engine lookup delays, this "
             "field may not be "
             "available yet.",
             req_both_arg},
            {ft::FTYPE_STRING, "container.image.repository", "Repository",
             "The container image repository (e.g. falcosecurity/falco). In "
             "instances of userspace "
             "container engine lookup delays, this field may not be available "
             "yet."},
            {ft::FTYPE_STRING, "container.image.tag", "Image Tag",
             "The container image tag (e.g. stable, latest). In instances of "
             "userspace container "
             "engine lookup delays, this field may not be available yet."},
            {ft::FTYPE_STRING, "container.image.digest", "Registry Digest",
             "The container image registry digest (e.g. "
             "sha256:"
             "d977378f890d445c15e51795296e4e5062f109ce6da83e0a355fc4ad8699d27)."
             " In instances of "
             "userspace container engine lookup delays, this field may not be "
             "available yet."},
            {ft::FTYPE_STRING, "container.healthcheck", "Health Check",
             "The container's health check. Will be the null value (\"N/A\") "
             "if no healthcheck "
             "configured, \"NONE\" if configured but explicitly not created, "
             "and the healthcheck "
             "command line otherwise. In instances of userspace container "
             "engine lookup delays, this "
             "field may not be available yet."},
            {ft::FTYPE_STRING, "container.liveness_probe", "Liveness",
             "The container's liveness probe. Will be the null value (\"N/A\") "
             "if no liveness probe "
             "configured, the liveness probe command line otherwise. In "
             "instances of userspace "
             "container engine lookup delays, this field may not be available "
             "yet."},
            {ft::FTYPE_STRING, "container.readiness_probe", "Readiness",
             "The container's readiness probe. Will be the null value "
             "(\"N/A\") if no readiness probe "
             "configured, the readiness probe command line otherwise. In "
             "instances of userspace "
             "container engine lookup delays, this field may not be available "
             "yet."},
            {ft::FTYPE_ABSTIME, "container.start_ts", "Container Start",
             "Container start as epoch timestamp in nanoseconds based on "
             "proc.pidns_init_start_ts and "
             "extracted in the kernel and not from the container runtime "
             "socket / container engine."},
            {ft::FTYPE_RELTIME, "container.duration", "Container Duration",
             "Number of nanoseconds since container.start_ts."},
            {ft::FTYPE_STRING, "container.ip", "Container ip address",
             "The container's / pod's primary ip address as retrieved from the "
             "container engine. Only "
             "ipv4 addresses are tracked. Consider container.cni.json (CRI use "
             "case) for logging ip "
             "addresses for each network interface. In instances of userspace "
             "container engine lookup "
             "delays, this field may not be available yet."},
            {ft::FTYPE_STRING, "container.cni.json",
             "Container's / pod's CNI result json",
             "The container's / pod's CNI result field from the respective pod "
             "status info. It "
             "contains ip addresses for each network interface exposed as "
             "unparsed escaped JSON "
             "string. Supported for CRI container engine (containerd, cri-o "
             "runtimes), optimized for "
             "containerd (some non-critical JSON keys removed). Useful for "
             "tracking ips (ipv4 and "
             "ipv6, dual-stack support) for each network interface "
             "(multi-interface support). In "
             "instances of userspace container engine lookup delays, this "
             "field may not be available "
             "yet."},
            {ft::FTYPE_BOOL, "container.host_pid", "Host PID Namespace",
             "'true' if the container is running in the host PID namespace, "
             "'false' otherwise."},
            {ft::FTYPE_BOOL, "container.host_network", "Host Network Namespace",
             "'true' if the container is running in the host network "
             "namespace, 'false' otherwise."},
            {ft::FTYPE_BOOL, "container.host_ipc", "Host IPC Namespace",
             "'true' if the container is running in the host IPC namespace, "
             "'false' otherwise."},
            {ft::FTYPE_STRING, "container.label", "Container Label",
             "Container label. E.g. 'container.label.foo'.", req_key_arg},
            {ft::FTYPE_STRING, "container.labels", "Container Labels",
             "Container comma-separated key/value labels. E.g. "
             "'foo1:bar1,foo2:bar2'."},
            {ft::FTYPE_BOOL, "proc.is_container_healthcheck",
             "Process Is Container Healthcheck",
             "'true' if this process is running as a part of the container's "
             "health check."},
            {ft::FTYPE_BOOL, "proc.is_container_liveness_probe",
             "Process Is Container Liveness",
             "'true' if this process is running as a part of the container's "
             "liveness probe."},
            {ft::FTYPE_BOOL, "proc.is_container_readiness_probe",
             "Process Is Container Readiness",
             "'true' if this process is running as a part of the container's "
             "readiness probe."},
            {ft::FTYPE_STRING, "k8s.pod.name", "Pod Name",
             "The Kubernetes pod name. This field is extracted from the "
             "container runtime socket "
             "simultaneously as we look up the 'container.*' fields. In cases "
             "of lookup delays, it may "
             "not be available yet."},
            {ft::FTYPE_STRING, "k8s.ns.name", "Namespace Name",
             "The Kubernetes namespace name. This field is extracted from the "
             "container runtime socket "
             "simultaneously as we look up the 'container.*' fields. In cases "
             "of lookup delays, it may "
             "not be available yet."},
            {ft::FTYPE_STRING, "k8s.pod.id", "Legacy Pod UID",
             "[LEGACY] The Kubernetes pod UID, e.g. "
             "3e41dc6b-08a8-44db-bc2a-3724b18ab19a. This legacy "
             "field points to `k8s.pod.uid`; however, the pod ID typically "
             "refers to the pod sandbox "
             "ID. We recommend using the semantically more accurate "
             "`k8s.pod.uid` field. This field is "
             "extracted from the container runtime socket simultaneously as we "
             "look up the "
             "'container.*' fields. In cases of lookup delays, it may not be "
             "available yet."},
            {ft::FTYPE_STRING, "k8s.pod.uid", "Pod UID",
             "The Kubernetes pod UID, e.g. "
             "3e41dc6b-08a8-44db-bc2a-3724b18ab19a. Note that the pod UID "
             "is a unique identifier assigned upon pod creation within "
             "Kubernetes, allowing the "
             "Kubernetes control plane to manage and track pods reliably. As "
             "such, it is fundamentally "
             "a different concept compared to the pod sandbox ID. This field "
             "is extracted from the "
             "container runtime socket simultaneously as we look up the "
             "'container.*' fields. In cases "
             "of lookup delays, it may not be available yet."},
            {ft::FTYPE_STRING, "k8s.pod.sandbox_id", "Pod / Sandbox ID",
             "The truncated Kubernetes pod sandbox ID (first 12 characters), "
             "e.g 63060edc2d3a. The "
             "sandbox ID is specific to the container runtime environment. It "
             "is the equivalent of the "
             "container ID for the pod / sandbox and extracted from the Linux "
             "cgroups. As such, it "
             "differs from the pod UID. This field is extracted from the "
             "container runtime socket "
             "simultaneously as we look up the 'container.*' fields. In cases "
             "of lookup delays, it may "
             "not be available yet. In Kubernetes, pod sandbox container "
             "processes can exist where "
             "`container.id` matches `k8s.pod.sandbox_id`, lacking other "
             "'container.*' details."},
            {ft::FTYPE_STRING, "k8s.pod.full_sandbox_id", "Pod / Sandbox ID",
             "The full Kubernetes pod / sandbox ID, e.g "
             "63060edc2d3aa803ab559f2393776b151f99fc5b05035b21db66b3b62246ad6a."
             " This field is "
             "extracted from the container runtime socket simultaneously as we "
             "look up the "
             "'container.*' fields. In cases of lookup delays, it may not be "
             "available yet."},
            {ft::FTYPE_STRING, "k8s.pod.label", "Pod Label",
             "The Kubernetes pod label. The label can be accessed either with "
             "the familiar brackets "
             "notation, e.g. 'k8s.pod.label[foo]' or by appending a dot "
             "followed by the name, e.g. "
             "'k8s.pod.label.foo'. The label name itself can include the "
             "original special characters "
             "such as '.', '-', '_' or '/' characters. For instance, "
             "'k8s.pod.label[app.kubernetes.io/name]', "
             "'k8s.pod.label.app.kubernetes.io/name' or "
             "'k8s.pod.label[custom-label_one]' are all valid. This field is "
             "extracted from the "
             "container runtime socket simultaneously as we look up the "
             "'container.*' fields. In cases "
             "of lookup delays, it may not be available yet.",
             req_key_arg},
            {ft::FTYPE_STRING, "k8s.pod.labels", "Pod Labels",
             "The Kubernetes pod comma-separated key/value labels. E.g. "
             "'foo1:bar1,foo2:bar2'. This "
             "field is extracted from the container runtime socket "
             "simultaneously as we look up the "
             "'container.*' fields. In cases of lookup delays, it may not be "
             "available yet."},
            {ft::FTYPE_STRING, "k8s.pod.ip", "Pod Ip",
             "The Kubernetes pod ip, same as container.ip field as each "
             "container in a pod shares the "
             "network stack of the sandbox / pod. Only ipv4 addresses are "
             "tracked. Consider "
             "k8s.pod.cni.json for logging ip addresses for each network "
             "interface. This field is "
             "extracted from the container runtime socket simultaneously as we "
             "look up the "
             "'container.*' fields. In cases of lookup delays, it may not be "
             "available yet."},
            {ft::FTYPE_STRING, "k8s.pod.cni.json", "Pod CNI result json",
             "The Kubernetes pod CNI result field from the respective pod "
             "status info, same as "
             "container.cni.json field. It contains ip addresses for each "
             "network interface exposed as "
             "unparsed escaped JSON string. Supported for CRI container engine "
             "(containerd, cri-o "
             "runtimes), optimized for containerd (some non-critical JSON keys "
             "removed). Useful for "
             "tracking ips (ipv4 and ipv6, dual-stack support) for each "
             "network interface "
             "(multi-interface support). This field is extracted from the "
             "container runtime socket "
             "simultaneously as we look up the 'container.*' fields. In cases "
             "of lookup delays, it may "
             "not be available yet."},
            {ft::FTYPE_STRING, "k8s.rc.name",
             "[Deprecated] Replication Controller Name",
             "Kubernetes replication controller name."},
            {ft::FTYPE_STRING, "k8s.rc.id",
             "[Deprecated] Replication Controller ID",
             "Kubernetes replication controller id."},
            {ft::FTYPE_STRING, "k8s.rc.label",
             "[Deprecated] Replication Controller Label",
             "Kubernetes replication controller label. E.g. "
             "'k8s.rc.label.foo'.",
             req_key_arg},
            {ft::FTYPE_STRING, "k8s.rc.labels",
             "[Deprecated] Replication Controller Labels",
             "Kubernetes replication controller comma-separated key/value "
             "labels. E.g. "
             "'foo1:bar1,foo2:bar2'."},
            {ft::FTYPE_STRING, "k8s.svc.name", "[Deprecated] Service Name",
             "Kubernetes service name (can return more than one value, "
             "concatenated)."},
            {ft::FTYPE_STRING, "k8s.svc.id", "[Deprecated] Service ID",
             "Kubernetes service id (can return more than one value, "
             "concatenated)."},
            {ft::FTYPE_STRING, "k8s.svc.label", "[Deprecated] Service Label",
             "Kubernetes service label. E.g. 'k8s.svc.label.foo' (can return "
             "more than one value, "
             "concatenated).",
             req_key_arg},
            {ft::FTYPE_STRING, "k8s.svc.labels", "[Deprecated] Service Labels",
             "Kubernetes service comma-separated key/value labels. E.g. "
             "'foo1:bar1,foo2:bar2'."},
            {ft::FTYPE_STRING, "k8s.ns.id", "[Deprecated] Namespace ID",
             "Kubernetes namespace id."},
            {ft::FTYPE_STRING, "k8s.ns.label", "[Deprecated] Namespace Label",
             "Kubernetes namespace label. E.g. 'k8s.ns.label.foo'.",
             req_key_arg},
            {ft::FTYPE_STRING, "k8s.ns.labels", "[Deprecated] Namespace Labels",
             "Kubernetes namespace comma-separated key/value labels. E.g. "
             "'foo1:bar1,foo2:bar2'."},
            {ft::FTYPE_STRING, "k8s.rs.name", "[Deprecated] Replica Set Name",
             "Kubernetes replica set name."},
            {ft::FTYPE_STRING, "k8s.rs.id", "[Deprecated] Replica Set ID",
             "Kubernetes replica set id."},
            {ft::FTYPE_STRING, "k8s.rs.label", "[Deprecated] Replica Set Label",
             "Kubernetes replica set label. E.g. 'k8s.rs.label.foo'.",
             req_key_arg},
            {ft::FTYPE_STRING, "k8s.rs.labels",
             "[Deprecated] Replica Set Labels",
             "Kubernetes replica set comma-separated key/value labels. E.g. "
             "'foo1:bar1,foo2:bar2'."},
            {ft::FTYPE_STRING, "k8s.deployment.name",
             "[Deprecated] Deployment Name", "Kubernetes deployment name."},
            {ft::FTYPE_STRING, "k8s.deployment.id",
             "[Deprecated] Deployment ID", "Kubernetes deployment id."},
            {ft::FTYPE_STRING, "k8s.deployment.label",
             "[Deprecated] Deployment Label",
             "Kubernetes deployment label. E.g. 'k8s.rs.label.foo'.",
             req_key_arg},
            {ft::FTYPE_STRING, "k8s.deployment.labels",
             "[Deprecated] Deployment Labels",
             "Kubernetes deployment comma-separated key/value labels. E.g. "
             "'foo1:bar1,foo2:bar2'."},
    };
    const int fields_size = sizeof(fields) / sizeof(fields[0]);
    static_assert(fields_size == TYPE_CONTAINER_FIELD_MAX,
                  "Wrong number of container fields.");
    return std::vector<falcosecurity::field_info>(fields, fields + fields_size);
}

static inline void
concatenate_container_labels(const std::map<std::string, std::string> &labels,
                             std::string *s)
{
    for(auto const &label_pair : labels)
    {
        // exclude annotations and internal labels
        if(label_pair.first.find("annotation.") == 0 ||
           label_pair.first.find("io.kubernetes.") == 0)
        {
            continue;
        }
        if(!s->empty())
        {
            s->append(", ");
        }
        s->append(label_pair.first);
        if(!label_pair.second.empty())
        {
            s->append(":" + label_pair.second);
        }
    }
}

bool my_plugin::extract(const falcosecurity::extract_fields_input &in)
{
    const auto evt_reader = in.get_event_reader();
    auto thread_id = evt_reader.get_tid();
    auto &req = in.get_extract_request();
    const auto field_id = req.get_field_id();
    auto tr = in.get_table_reader();
    bool is_container_async_event = false;

    std::shared_ptr<const container_info> cinfo;
    // NOTE: empty in case we are extracting from an event generated by us.
    // Not a big deal since cinfo will always be != null in that case.
    std::string container_id;
    // NOTE: empty in case we are extracting from an event generated by us.
    // This means that any request to extract from it (eg:
    // TYPE_CONTAINER_DURATION) will throw an exception and MUST be managed.
    falcosecurity::table_entry thread_entry;

    // If it is an async event, try to understand whether it is a `container`
    // async event
    if(evt_reader.get_type() == PPME_ASYNCEVENT_E)
    {
        falcosecurity::events::asyncevent_e_decoder ad(evt_reader);
        is_container_async_event =
                std::strcmp(ad.get_name(), ASYNC_EVENT_NAME_ADDED) == 0;
    }
    // For events generated by us, use the last container added to fetch info.
    if(evt_reader.get_type() == PPME_CONTAINER_E ||
       evt_reader.get_type() == PPME_CONTAINER_JSON_E ||
       evt_reader.get_type() == PPME_CONTAINER_JSON_2_E ||
       is_container_async_event)
    {

        // We just generated a container and we are asked to parse from it; use
        // it.
        cinfo = m_last_container;
    }
    else
    {
        try
        {
            // retrieve the thread entry associated with this thread id
            thread_entry = m_threads_table.get_entry(tr, thread_id);
            // retrieve container_id from the entry
            m_container_id_field.read_value(tr, thread_entry, container_id);
        }
        catch(falcosecurity::plugin_exception e)
        {
            // Debug here since many events do not have thread id info (eg:
            // schedswitch)
            m_logger.log(
                    fmt::format(
                            "cannot extract the container_id for the thread id "
                            "'{}': {}",
                            thread_id, e.what()),
                    falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
            return false;
        }

        // Try to find the entry associated with the container_id
        auto it = m_containers.find(container_id);
        if(it == m_containers.end())
        {
            m_logger.log(
                    fmt::format(
                            "the plugin has no info for the container id '{}'",
                            container_id),
                    falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
            if(field_id != TYPE_CONTAINER_ID &&
               field_id != TYPE_CONTAINER_START_TS &&
               field_id != TYPE_CONTAINER_DURATION &&
               field_id != TYPE_IS_CONTAINER_HEALTHCHECK &&
               field_id != TYPE_IS_CONTAINER_LIVENESS_PROBE &&
               field_id != TYPE_IS_CONTAINER_READINESS_PROBE)
            {
                // Can't return anything but those fields without containers
                // metadata.

                // Set an empty extracted value to let `return true` below work
                // See
                // https://github.com/falcosecurity/libs/blob/0d94d2bc55d4ccde870bc0c076423a1e13814079/userspace/libsinsp/plugin_filtercheck.cpp#L172
                req.set_value("");
                return true; // go on to extract other fields if needed, perhaps
                             // they'll be one of the above
            }
        }
        else
        {
            cinfo = it->second;
        }
    }

    switch(field_id)
    {
    case TYPE_CONTAINER_ID:
        if(cinfo != nullptr)
        {
            req.set_value(cinfo->m_id);
        }
        else
        {
            // We don't have container metadatas but we are in a container.
            req.set_value(container_id);
        }
        break;
    case TYPE_CONTAINER_FULL_CONTAINER_ID:
        req.set_value(cinfo->m_full_id);
        break;
    case TYPE_CONTAINER_NAME:
        req.set_value(cinfo->m_name);
        break;
    case TYPE_CONTAINER_IMAGE:
        req.set_value(cinfo->m_image);
        break;
    case TYPE_CONTAINER_IMAGE_ID:
        req.set_value(cinfo->m_imageid);
        break;
    case TYPE_CONTAINER_TYPE:
        req.set_value(to_string(cinfo->m_type));
        break;
    case TYPE_CONTAINER_PRIVILEGED:
        req.set_value(cinfo->m_privileged);
        break;
    case TYPE_CONTAINER_MOUNTS:
    {
        std::string tstr;
        bool first = true;
        for(auto &mntinfo : cinfo->m_mounts)
        {
            if(first)
            {
                first = false;
            }
            else
            {
                tstr += ",";
            }
            tstr += mntinfo.to_string();
        }
        req.set_value(tstr);
        break;
    }
    case TYPE_CONTAINER_MOUNT:
    case TYPE_CONTAINER_MOUNT_SOURCE:
    case TYPE_CONTAINER_MOUNT_DEST:
    case TYPE_CONTAINER_MOUNT_MODE:
    case TYPE_CONTAINER_MOUNT_RDWR:
    case TYPE_CONTAINER_MOUNT_PROPAGATION:
    {
        const container_mount_info *mntinfo;
        auto arg_id = req.get_arg_index();
        if(arg_id != -1)
        {
            mntinfo = cinfo->mount_by_idx(arg_id);
        }
        else
        {
            auto arg_key = req.get_arg_key();
            // See
            // https://github.com/falcosecurity/libs/blob/d87c96b50545bb192fa2a517afce76383877cab5/userspace/libsinsp/sinsp_filtercheck_container.cpp#L617
            if(field_id == TYPE_CONTAINER_MOUNT_SOURCE)
            {
                mntinfo = cinfo->mount_by_dest(arg_key);
            }
            else
            {
                mntinfo = cinfo->mount_by_source(arg_key);
            }
        }
        if(mntinfo)
        {
            std::string tstr;
            switch(field_id)
            {
            case TYPE_CONTAINER_MOUNT:
                tstr = mntinfo->to_string();
                break;
            case TYPE_CONTAINER_MOUNT_SOURCE:
                tstr = mntinfo->m_source;
                break;
            case TYPE_CONTAINER_MOUNT_DEST:
                tstr = mntinfo->m_dest;
                break;
            case TYPE_CONTAINER_MOUNT_MODE:
                tstr = mntinfo->m_mode;
                break;
            case TYPE_CONTAINER_MOUNT_RDWR:
                tstr = (mntinfo->m_rdwr ? "true" : "false");
                break;
            case TYPE_CONTAINER_MOUNT_PROPAGATION:
                tstr = mntinfo->m_propagation;
                break;
            }
            req.set_value(tstr);
        }
        break;
    }
    case TYPE_CONTAINER_IMAGE_REPOSITORY:
        req.set_value(cinfo->m_imagerepo);
        break;
    case TYPE_CONTAINER_IMAGE_TAG:
        req.set_value(cinfo->m_imagetag);
        break;
    case TYPE_CONTAINER_IMAGE_DIGEST:
        req.set_value(cinfo->m_imagedigest);
        break;
    case TYPE_CONTAINER_HEALTHCHECK:
    case TYPE_CONTAINER_LIVENESS_PROBE:
    case TYPE_CONTAINER_READINESS_PROBE:
    {
        std::string tstr = "NONE";
        bool set = false;
        for(auto &probe : cinfo->m_health_probes)
        {
            if((field_id == TYPE_CONTAINER_HEALTHCHECK &&
                probe.m_type == container_health_probe::PT_HEALTHCHECK) ||
               (field_id == TYPE_CONTAINER_LIVENESS_PROBE &&
                probe.m_type == container_health_probe::PT_LIVENESS_PROBE) ||
               (field_id == TYPE_CONTAINER_READINESS_PROBE &&
                probe.m_type == container_health_probe::PT_READINESS_PROBE))
            {
                tstr = probe.m_exe;

                for(auto &arg : probe.m_args)
                {
                    tstr += " ";
                    tstr += arg;
                }
                req.set_value(tstr);
                set = true;
                break;
            }
        }
        if(!set)
        {
            req.set_value(tstr);
        }
        break;
    }
    case TYPE_CONTAINER_START_TS:
    case TYPE_CONTAINER_DURATION:
    {
        uint64_t pidns_init_start_ts;
        try
        {
            m_threads_field_pidns_init_start_ts.read_value(tr, thread_entry,
                                                           pidns_init_start_ts);
        }
        catch(...)
        {
            pidns_init_start_ts = 0;
        }
        if(pidns_init_start_ts != 0)
        {
            if(field_id == TYPE_CONTAINER_START_TS)
            {
                req.set_value(pidns_init_start_ts);
            }
            else
            {
                req.set_value(evt_reader.get_ts() - pidns_init_start_ts);
            }
        }
        break;
    }
    case TYPE_CONTAINER_IP_ADDR:
        req.set_value(cinfo->m_container_ip);
        break;
    case TYPE_CONTAINER_CNIRESULT:
        req.set_value(cinfo->m_pod_sandbox_cniresult);
        break;
    case TYPE_CONTAINER_HOST_PID:
        req.set_value(cinfo->m_host_pid);
        break;
    case TYPE_CONTAINER_HOST_NETWORK:
        req.set_value(cinfo->m_host_network);
        break;
    case TYPE_CONTAINER_HOST_IPC:
        req.set_value(cinfo->m_host_ipc);
        break;
    case TYPE_CONTAINER_LABEL:
    {
        auto arg_key = req.get_arg_key();
        if(cinfo->m_labels.count(arg_key) > 0)
        {
            req.set_value(cinfo->m_labels.at(arg_key));
        }
        break;
    }
    case TYPE_CONTAINER_LABELS:
    {
        std::string labels;
        concatenate_container_labels(cinfo->m_labels, &labels);
        req.set_value(labels);
        break;
    }
    case TYPE_K8S_POD_NAME:
        if(cinfo->m_labels.count("io.kubernetes.pod.name") > 0)
        {
            req.set_value(cinfo->m_labels.at("io.kubernetes.pod.name"));
        }
        break;
    case TYPE_K8S_NS_NAME:
        if(cinfo->m_labels.count("io.kubernetes.pod.namespace") > 0)
        {
            req.set_value(cinfo->m_labels.at("io.kubernetes.pod.namespace"));
        }
        break;
    case TYPE_K8S_POD_ID:
    case TYPE_K8S_POD_UID:
        if(cinfo->m_labels.count("io.kubernetes.pod.uid") > 0)
        {
            req.set_value(cinfo->m_labels.at("io.kubernetes.pod.uid"));
        }
        break;
    case TYPE_K8S_POD_SANDBOX_ID:
    case TYPE_K8S_POD_FULL_SANDBOX_ID:
    {
        auto sandbox_id = cinfo->m_pod_sandbox_id;
        if(field_id == TYPE_K8S_POD_SANDBOX_ID)
        {
            if(sandbox_id.size() > SHORT_ID_LEN)
            {
                sandbox_id.resize(SHORT_ID_LEN);
            }
        }
        req.set_value(sandbox_id);
        break;
    }
    case TYPE_K8S_POD_LABEL:
    case TYPE_K8S_POD_LABELS:
    {
        std::shared_ptr<const container_info> sandbox_container_info;
        if(cinfo->m_pod_sandbox_cniresult.empty())
        {
            // Fallback: Retrieve PodSandboxStatusResponse fields stored in
            // explicit pod sandbox container
            auto sandbox_id = cinfo->m_pod_sandbox_id.substr(0, SHORT_ID_LEN);
            if(m_containers.count(sandbox_id) > 0)
            {
                sandbox_container_info = m_containers[sandbox_id];
            }
        }
        if(field_id == TYPE_K8S_POD_LABEL)
        {
            auto arg_key = req.get_arg_key();
            if(sandbox_container_info &&
               sandbox_container_info->m_pod_sandbox_labels.count(arg_key) > 0)
            {
                req.set_value(sandbox_container_info->m_pod_sandbox_labels.at(
                        arg_key));
            }
            else if(cinfo->m_pod_sandbox_labels.count(arg_key) > 0)
            {
                req.set_value(cinfo->m_pod_sandbox_labels.at(arg_key));
            }
        }
        else
        {
            std::string labels;
            if(sandbox_container_info)
            {
                concatenate_container_labels(
                        sandbox_container_info->m_pod_sandbox_labels, &labels);
            }
            else
            {
                concatenate_container_labels(cinfo->m_pod_sandbox_labels,
                                             &labels);
            }
            req.set_value(labels);
        }
        break;
    }
    case TYPE_K8S_POD_IP:
        if(cinfo->m_pod_sandbox_cniresult.empty())
        {
            auto sandbox_id = cinfo->m_pod_sandbox_id.substr(0, SHORT_ID_LEN);
            if(m_containers.count(sandbox_id) > 0)
            {
                auto &sandbox_container_info = m_containers[sandbox_id];
                req.set_value(sandbox_container_info->m_container_ip);
            }
        }
        else
        {
            req.set_value(cinfo->m_container_ip);
        }
        break;
    case TYPE_K8S_POD_CNIRESULT:
        if(cinfo->m_pod_sandbox_cniresult.empty())
        {
            auto sandbox_id = cinfo->m_pod_sandbox_id.substr(0, SHORT_ID_LEN);
            if(m_containers.count(sandbox_id) > 0)
            {
                auto &sandbox_container_info = m_containers[sandbox_id];
                req.set_value(sandbox_container_info->m_pod_sandbox_cniresult);
            }
        }
        else
        {
            req.set_value(cinfo->m_pod_sandbox_cniresult);
        }
        break;
    case TYPE_IS_CONTAINER_HEALTHCHECK:
    {
        int16_t category;
        // Since we do write thread category only if not NONE for containerized
        // processes
        try
        {
            m_threads_field_category.read_value(tr, thread_entry, category);
        }
        catch(...)
        {
            category = CAT_NONE;
        }
        req.set_value(category == CAT_HEALTHCHECK);
        break;
    }
    case TYPE_IS_CONTAINER_LIVENESS_PROBE:
    {
        int16_t category;
        // Since we do write thread category only if not NONE for containerized
        // processes
        try
        {
            m_threads_field_category.read_value(tr, thread_entry, category);
        }
        catch(...)
        {
            category = CAT_NONE;
        }
        req.set_value(category == CAT_LIVENESS_PROBE);
        break;
    }
    case TYPE_IS_CONTAINER_READINESS_PROBE:
    {
        int16_t category;
        // Since we do write thread category only if not NONE for containerized
        // processes
        try
        {
            m_threads_field_category.read_value(tr, thread_entry, category);
        }
        catch(...)
        {
            category = CAT_NONE;
        }
        req.set_value(category == CAT_READINESS_PROBE);
        break;
    }
    case TYPE_K8S_RC_NAME:
    case TYPE_K8S_RC_ID:
    case TYPE_K8S_RC_LABEL:
    case TYPE_K8S_RC_LABELS:
    case TYPE_K8S_SVC_NAME:
    case TYPE_K8S_SVC_ID:
    case TYPE_K8S_SVC_LABEL:
    case TYPE_K8S_SVC_LABELS:
    case TYPE_K8S_NS_ID:
    case TYPE_K8S_NS_LABEL:
    case TYPE_K8S_NS_LABELS:
    case TYPE_K8S_RS_NAME:
    case TYPE_K8S_RS_ID:
    case TYPE_K8S_RS_LABEL:
    case TYPE_K8S_RS_LABELS:
    case TYPE_K8S_DEPLOYMENT_NAME:
    case TYPE_K8S_DEPLOYMENT_ID:
    case TYPE_K8S_DEPLOYMENT_LABEL:
    case TYPE_K8S_DEPLOYMENT_LABELS:
        // Deprecated fields don't extract anything
        break;
    default:
        m_logger.log(fmt::format("unknown extraction request on field '{}' for "
                                 "container_id '{}'",
                                 req.get_field_id(), container_id),
                     falcosecurity::_internal::SS_PLUGIN_LOG_SEV_ERROR);
        return false;
    }
    return true;
}

FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(my_plugin);