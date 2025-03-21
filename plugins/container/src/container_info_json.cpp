#include "container_info.h"

/*
{
  "container": {
    "Mounts": [
      {
        "Destination": "/home/federico",
        "Mode": "",
        "Propagation": "rprivate",
        "RW": true,
        "Source": "/home/federico"
      }
    ],
    "User": "",
    "cni_json": "",
    "cpu_period": 100000,
    "cpu_quota": 0,
    "cpu_shares": 1024,
    "cpuset_cpu_count": 0,
    "created_time": 1730971086,
    "env": [],
    "full_id":
"32a1026ccb88a551e2a38eb8f260b4700aefec7e8c007344057e58a9fa302374", "host_ipc":
false, "host_network": false, "host_pid": false, "id": "32a1026ccb88", "image":
"fedora:38", "imagedigest":
"sha256:b9ff6f23cceb5bde20bb1f79b492b98d71ef7a7ae518ca1b15b26661a11e6a94",
    "imageid":
"0ca0fed353fb77c247abada85aebc667fd1f5fa0b5f6ab1efb26867ba18f2f0a", "imagerepo":
"fedora", "imagetag": "38", "ip": "172.17.0.2", "is_pod_sandbox": false,
    "labels": {
      "maintainer": "Clement Verna <cverna@fedoraproject.org>"
    },
    "lookup_state": 1,
    "memory_limit": 0,
    "metadata_deadline": 0,
    "name": "youthful_babbage",
    "pod_sandbox_id": "",
    "pod_sandbox_labels": null,
    "port_mappings": [],
    "privileged": false,
    "swap_limit": 0,
    "type": 0
  }
}
*/

void from_json(const nlohmann::json& j, container_health_probe& probe)
{
    probe.m_args = j.value("args", std::vector<std::string>{});
    probe.m_exe = j.value("exe", "");
}

void from_json(const nlohmann::json& j, container_mount_info& mount)
{
    mount.m_source = j.value("Source", "");
    mount.m_dest = j.value("Destination", "");
    mount.m_mode = j.value("Mode", "");
    mount.m_rdwr = j.value("RW", false);
    mount.m_propagation = j.value("Propagation", "");
}

void from_json(const nlohmann::json& j, container_port_mapping& port)
{
    port.m_host_ip = j.value("HostIp", 0);
    port.m_host_port = j.value("HostPort", 0);
    port.m_container_port = j.value("ContainerPort", 0);
}

/*
 * Since some old json pushed json entries like:
 * "pod_sandbox_labels": null
 * actually check that key does not hold a null value
 * when accessing objects.
 */
template<typename T>
static inline void object_from_json(const nlohmann::json& j, const char* key,
                                    T& obj)
{
    if(j.contains(key) && !j[key].is_null())
    {
        obj = j[key].get<T>();
    }
    else
    {
        obj = T();
    }
}

void from_json(const nlohmann::json& j, std::shared_ptr<container_info>& cinfo)
{
    std::shared_ptr<container_info> info = std::make_shared<container_info>();
    const nlohmann::json& container = j["container"];
    info->m_type = container.value("type", CT_UNKNOWN);
    info->m_id = container.value("id", "");
    info->m_name = container.value("name", "");
    info->m_image = container.value("image", "");
    info->m_imagedigest = container.value("imagedigest", "");
    info->m_imageid = container.value("imageid", "");
    info->m_imagerepo = container.value("imagerepo", "");
    info->m_imagetag = container.value("imagetag", "");
    info->m_container_user = container.value("User", "");
    info->m_pod_sandbox_cniresult = container.value("cni_json", "");
    info->m_cpu_period = container.value("cpu_period", 0);
    info->m_cpu_quota = container.value("cpu_quota", 0);
    info->m_cpu_shares = container.value("cpu_shares", 0);
    info->m_cpuset_cpu_count = container.value("cpuset_cpu_count", 0);
    info->m_created_time = container.value("created_time", 0);
    info->m_size_rw_bytes = container.value("size", -1);
    object_from_json(container, "env", info->m_env);
    info->m_full_id = container.value("full_id", "");
    info->m_host_ipc = container.value("host_ipc", false);
    info->m_host_network = container.value("host_network", false);
    info->m_host_pid = container.value("host_pid", false);
    info->m_container_ip = container.value("ip", "");
    info->m_is_pod_sandbox = container.value("is_pod_sandbox", false);
    object_from_json(container, "labels", info->m_labels);
    info->m_memory_limit = container.value("memory_limit", 0);
    info->m_swap_limit = container.value("swap_limit", 0);
    info->m_pod_sandbox_id = container.value("pod_sandbox_id", "");
    info->m_privileged = container.value("privileged", false);
    object_from_json(container, "pod_sandbox_labels",
                     info->m_pod_sandbox_labels);
    object_from_json(container, "port_mappings", info->m_port_mappings);
    object_from_json(container, "Mounts", info->m_mounts);

    for(int probe_type = container_health_probe::PT_HEALTHCHECK;
        probe_type <= container_health_probe::PT_READINESS_PROBE; probe_type++)
    {
        const auto& probe_name =
                container_health_probe::probe_type_names[probe_type];
        if(container.contains(probe_name))
        {
            container_health_probe probe =
                    container.value(probe_name, container_health_probe());
            probe.m_type = container_health_probe::probe_type(probe_type);
            info->m_health_probes.push_back(probe);
        }
    }

    cinfo = info;
}

void to_json(nlohmann::json& j, const container_health_probe& probe)
{
    j["args"] = probe.m_args;
    j["exe"] = probe.m_exe;
}

void to_json(nlohmann::json& j, const container_mount_info& mount)
{
    j["Source"] = mount.m_source;
    j["Destination"] = mount.m_dest;
    j["Mode"] = mount.m_mode;
    j["RW"] = mount.m_rdwr;
    j["Propagation"] = mount.m_propagation;
}

void to_json(nlohmann::json& j, const container_port_mapping& port)
{
    j["HostIp"] = port.m_host_ip;
    j["HostPort"] = port.m_host_port;
    j["ContainerPort"] = port.m_container_port;
}

void to_json(nlohmann::json& j,
             const std::shared_ptr<const container_info>& cinfo)
{
    auto& container = j["container"];
    j["type"] = cinfo->m_type;
    j["id"] = cinfo->m_id;
    j["name"] = cinfo->m_name;
    j["image"] = cinfo->m_image;
    j["imagedigest"] = cinfo->m_imagedigest;
    j["imageid"] = cinfo->m_imageid;
    j["imagerepo"] = cinfo->m_imagerepo;
    j["imagetag"] = cinfo->m_imagetag;
    j["User"] = cinfo->m_container_user;
    j["cni_json"] = cinfo->m_pod_sandbox_cniresult;
    j["cpu_period"] = cinfo->m_cpu_period;
    j["cpu_quota"] = cinfo->m_cpu_quota;
    j["cpu_shares"] = cinfo->m_cpu_shares;
    j["cpuset_cpu_count"] = cinfo->m_cpuset_cpu_count;
    j["created_time"] = cinfo->m_created_time;
    j["size"] = cinfo->m_size_rw_bytes;
    // TODO: only append a limited set of env?
    // https://github.com/falcosecurity/libs/blob/master/userspace/libsinsp/container.cpp#L232
    j["env"] = cinfo->m_env;
    j["full_id"] = cinfo->m_full_id;
    j["host_ipc"] = cinfo->m_host_ipc;
    j["host_network"] = cinfo->m_host_network;
    j["host_pid"] = cinfo->m_host_pid;
    j["ip"] = cinfo->m_container_ip;
    j["is_pod_sandbox"] = cinfo->m_is_pod_sandbox;
    j["labels"] = cinfo->m_labels;
    j["memory_limit"] = cinfo->m_memory_limit;
    j["swap_limit"] = cinfo->m_swap_limit;
    j["pod_sandbox_id"] = cinfo->m_pod_sandbox_id;
    j["privileged"] = cinfo->m_privileged;
    j["pod_sandbox_labels"] = cinfo->m_pod_sandbox_labels;
    j["port_mappings"] = cinfo->m_port_mappings;
    j["Mounts"] = cinfo->m_mounts;

    for(auto& probe : cinfo->m_health_probes)
    {
        const auto probe_type =
                container_health_probe::probe_type_names[probe.m_type];
        j[probe_type] = probe;
    }
}