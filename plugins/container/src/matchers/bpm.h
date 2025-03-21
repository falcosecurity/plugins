#pragma once

#include "matcher.h"

class bpm : public cgroup_matcher
{
    bool resolve(const std::string& cgroup, std::string& container_id) override;
    std::shared_ptr<container_info>
    to_container(const std::string& container_id) override;
};
