#include "matcher.h"
#include "docker.h"
#include "bpm.h"
#include "podman.h"
#include "cri.h"
#include "containerd.h"
#include "lxc.h"
#include "libvirt_lxc.h"
#include "static_container.h"

matcher_manager::matcher_manager(const Engines& cfg)
{
    if(cfg.static_ctr.enabled)
    {
        // Configured with a static engine; add it and return.
        auto engine = std::make_shared<static_container>(
                cfg.static_ctr.id, cfg.static_ctr.name, cfg.static_ctr.image);
        m_cgroup_matchers.push_back(engine);
        return;
    }

    if(cfg.podman.enabled)
    {
        auto podman_engine = std::make_shared<podman>();
        m_cgroup_matchers.push_back(podman_engine);
    }
    if(cfg.docker.enabled)
    {
        auto docker_engine = std::make_shared<docker>();
        m_cgroup_matchers.push_back(docker_engine);
    }
    if(cfg.cri.enabled)
    {
        auto cri_engine = std::make_shared<cri>();
        m_cgroup_matchers.push_back(cri_engine);
    }
    if(cfg.containerd.enabled)
    {
        auto containerd_engine = std::make_shared<containerd>();
        m_cgroup_matchers.push_back(containerd_engine);
    }
    if(cfg.lxc.enabled)
    {
        auto lxc_engine = std::make_shared<lxc>();
        m_cgroup_matchers.push_back(lxc_engine);
    }
    if(cfg.libvirt_lxc.enabled)
    {
        auto libvirt_lxc_engine = std::make_shared<libvirt_lxc>();
        m_cgroup_matchers.push_back(libvirt_lxc_engine);
    }
    if(cfg.bpm.enabled)
    {
        auto bpm_engine = std::make_shared<bpm>();
        m_cgroup_matchers.push_back(bpm_engine);
    }
}

bool matcher_manager::match_cgroup(const std::string& cgroup,
                                   std::string& container_id,
                                   container_info::ptr_t& ctr)
{
    std::pair<std::string, std::shared_ptr<cgroup_matcher>> cid_matcher_p;
    if(m_cgroup_cinfo_cache.get(cgroup, cid_matcher_p))
    {
        container_id = cid_matcher_p.first;
        if(cid_matcher_p.second != nullptr)
        {
            ctr = cid_matcher_p.second->to_container(container_id);
            return true;
        }
        else
        {
            return false;
        }
    }

    for(const auto& matcher : m_cgroup_matchers)
    {
        if(matcher->resolve(cgroup, container_id))
        {
            ctr = matcher->to_container(container_id);
            m_cgroup_cinfo_cache.set(cgroup, {container_id, matcher});
            return true;
        }
    }

    // If a cgroup does not match is host.
    m_cgroup_cinfo_cache.set(cgroup, {"", nullptr});
    return false;
}
