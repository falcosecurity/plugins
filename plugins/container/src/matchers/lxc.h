#pragma once

#include "matcher.h"

class lxc : public cgroup_matcher
{
    bool resolve(const std::string& cgroup, std::string& container_id) override;
    container_info::ptr_t
    to_container(const std::string& container_id) override;
};