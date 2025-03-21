#pragma once

#include <cassert>
#include <cstdint>
#include <map>
#include <memory>
#include <list>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "container_type.h"
#include "consts.h"

#define HOST_CONTAINER_ID "host"

class container_port_mapping
{
    public:
    container_port_mapping(): m_host_ip(0), m_host_port(0), m_container_port(0)
    {
    }
    uint32_t m_host_ip;
    uint16_t m_host_port;
    uint16_t m_container_port;
};

class container_mount_info
{
    public:
    container_mount_info():
            m_source(""), m_dest(""), m_mode(""), m_rdwr(false),
            m_propagation("")
    {
    }

    container_mount_info(const std::string&& source, const std::string&& dest,
                         const std::string&& mode, const bool rw,
                         const std::string&& propagation):
            m_source(source), m_dest(dest), m_mode(mode), m_rdwr(rw),
            m_propagation(propagation)
    {
    }

    std::string to_string() const
    {
        return m_source + ":" + m_dest + ":" + m_mode + ":" +
               (m_rdwr ? "true" : "false") + ":" + m_propagation;
    }

    std::string m_source;
    std::string m_dest;
    std::string m_mode;
    bool m_rdwr;
    std::string m_propagation;
};

class container_health_probe
{
    public:
    // The type of health probe
    enum probe_type
    {
        PT_NONE,
        PT_HEALTHCHECK,
        PT_LIVENESS_PROBE,
        PT_READINESS_PROBE
    };

    // String representations of the above, suitable for
    // parsing to/from json. Should be kept in sync with
    // probe_type enum.
    static std::vector<std::string> probe_type_names;

    container_health_probe();
    container_health_probe(const probe_type probe_type, const std::string&& exe,
                           const std::vector<std::string>&& args);
    virtual ~container_health_probe();

    // The probe_type that should be used for commands
    // matching this health probe.
    probe_type m_type;

    // The actual health probe exe and args.
    std::string m_exe;
    std::vector<std::string> m_args;
};

class container_info
{
    public:
    container_info():
            m_type(CT_UNKNOWN), m_privileged(false), m_host_pid(false),
            m_host_network(false), m_host_ipc(false), m_memory_limit(0),
            m_swap_limit(0), m_cpu_shares(1024), m_cpu_quota(0),
            m_cpu_period(100000), m_cpuset_cpu_count(0),
            m_is_pod_sandbox(false), m_size_rw_bytes(-1)
    {
    }

    const std::vector<std::string>& get_env() const { return m_env; }

    const container_mount_info* mount_by_idx(uint32_t idx) const;
    const container_mount_info* mount_by_source(const std::string&) const;
    const container_mount_info* mount_by_dest(const std::string&) const;

    bool is_pod_sandbox() const { return m_is_pod_sandbox; }

    // static utilities to build a container_info
    static std::shared_ptr<container_info> host_container_info()
    {
        auto host_info = std::make_shared<container_info>();
        host_info->m_id = HOST_CONTAINER_ID;
        host_info->m_full_id = HOST_CONTAINER_ID;
        host_info->m_name = HOST_CONTAINER_ID;
        host_info->m_type = CT_HOST;
        return host_info;
    }

    // Match a process against the set of health probes
    container_health_probe::probe_type
    match_health_probe(const std::string& exe,
                       const std::vector<std::string>& args) const;

    std::string m_id;
    std::string m_full_id;
    container_type m_type;
    std::string m_name;
    std::string m_image;
    std::string m_imageid;
    std::string m_imagerepo;
    std::string m_imagetag;
    std::string m_imagedigest;
    std::string m_container_ip; // TODO: to be exposed by state API
    bool m_privileged;
    bool m_host_pid;
    bool m_host_network;
    bool m_host_ipc;
    std::vector<container_mount_info> m_mounts;
    std::vector<container_port_mapping> m_port_mappings;
    std::map<std::string, std::string> m_labels;
    std::vector<std::string> m_env;
    int64_t m_memory_limit;
    int64_t m_swap_limit;
    int64_t m_cpu_shares;
    int64_t m_cpu_quota;
    int64_t m_cpu_period;
    int64_t m_cpuset_cpu_count;
    std::list<container_health_probe> m_health_probes;
    std::string m_pod_sandbox_id;
    std::map<std::string, std::string> m_pod_sandbox_labels;
    std::string m_pod_sandbox_cniresult;
    bool m_is_pod_sandbox;
    std::string m_container_user; // TODO: to be exposed by state API

    /**
     * The time at which the container was created (IN SECONDS), cast from a
     * value of `time_t` We choose int64_t as we are not certain what type
     * `time_t` is in a given implementation; int64_t is the safest bet. Many
     * default to int64_t anyway (e.g. CRI).
     */
    int64_t m_created_time;
    int64_t m_size_rw_bytes; // TODO: to be exposed by state API
};

/* Nlhomann adapters (implemented by container_info_json.cpp) */
void from_json(const nlohmann::json& j, container_health_probe& probe);
void from_json(const nlohmann::json& j, container_mount_info& mount);
void from_json(const nlohmann::json& j, container_port_mapping& port);
void from_json(const nlohmann::json& j, std::shared_ptr<container_info>& cinfo);

void to_json(nlohmann::json& j, const container_health_probe& probe);
void to_json(nlohmann::json& j, const container_mount_info& mount);
void to_json(nlohmann::json& j, const container_port_mapping& port);
void to_json(nlohmann::json& j,
             const std::shared_ptr<const container_info>& cinfo);