#pragma once

#include "matcher.h"

class podman : public cgroup_matcher
{
    bool resolve(const std::string& cgroup, std::string& container_id) override;
};
