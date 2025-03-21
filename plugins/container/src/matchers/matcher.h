#pragma once

#include "../container_info.h"
#include "../plugin_config.h"
#include <list>

class cgroup_matcher
{
    public:
    virtual bool resolve(const std::string& cgroup,
                         std::string& container_id) = 0;

    /// Some container engines only retrieve small metadata (eg: container_id
    /// and container type). For those, it's ok to immediately send the async
    /// event since we don't have to wait for the go-worker because they are not
    /// implemented in listener mode.
    virtual std::shared_ptr<container_info>
    to_container(const std::string& container_id)
    {
        return nullptr;
    }
};

class matcher_manager
{
    public:
    matcher_manager(const Engines& cfg);

    bool match_cgroup(const std::string& cgroup, std::string& container_id,
                      std::shared_ptr<container_info>& ctr);

    private:
    std::list<std::shared_ptr<cgroup_matcher>> m_matchers;
};