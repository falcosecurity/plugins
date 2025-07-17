#pragma once

#include "matcher.h"

class static_container : public cgroup_matcher
{
    public:
    static_container(const std::string& id, const std::string& name,
                     const std::string& image);

    bool resolve(const std::string& cgroup, std::string& container_id) override;
    container_info::ptr_t
    to_container(const std::string& container_id) override;

    private:
    container_info::ptr_t m_static_container_info;
};
