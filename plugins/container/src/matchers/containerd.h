#pragma once

#include "matcher.h"
#include <reflex/matcher.h>

class containerd : public cgroup_matcher
{
    public:
    containerd();
    bool resolve(const std::string& cgroup, std::string& container_id) override;

    private:
    reflex::Matcher m_matcher;
};
