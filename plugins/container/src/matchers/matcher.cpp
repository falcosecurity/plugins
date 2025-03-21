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
        m_matchers.push_back(engine);
        return;
    }

    if(cfg.podman.enabled)
    {
        auto podman_engine = std::make_shared<podman>();
        m_matchers.push_back(podman_engine);
    }
    if(cfg.docker.enabled)
    {
        auto docker_engine = std::make_shared<docker>();
        m_matchers.push_back(docker_engine);
    }
    if(cfg.cri.enabled)
    {
        auto cri_engine = std::make_shared<cri>();
        m_matchers.push_back(cri_engine);
    }
    if(cfg.containerd.enabled)
    {
        auto containerd_engine = std::make_shared<containerd>();
        m_matchers.push_back(containerd_engine);
    }
    if(cfg.lxc.enabled)
    {
        auto lxc_engine = std::make_shared<lxc>();
        m_matchers.push_back(lxc_engine);
    }
    if(cfg.libvirt_lxc.enabled)
    {
        auto libvirt_lxc_engine = std::make_shared<libvirt_lxc>();
        m_matchers.push_back(libvirt_lxc_engine);
    }
    if(cfg.bpm.enabled)
    {
        auto bpm_engine = std::make_shared<bpm>();
        m_matchers.push_back(bpm_engine);
    }
}

bool matcher_manager::match_cgroup(const std::string& cgroup,
                                   std::string& container_id,
                                   std::shared_ptr<container_info>& ctr)
{
    for(const auto& matcher : m_matchers)
    {
        if(matcher->resolve(cgroup, container_id))
        {
            ctr = matcher->to_container(container_id);
            return true;
        }
    }
    return false;
}