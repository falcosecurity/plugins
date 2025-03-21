// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <utility>
#include <reflex/matcher.h>
#include "container_info.h"

std::vector<std::string> container_health_probe::probe_type_names = {
        "None", "Healthcheck", "LivenessProbe", "ReadinessProbe"};

container_health_probe::container_health_probe(): m_type(PT_NONE) {}

container_health_probe::container_health_probe(
        const probe_type ptype, const std::string &&exe,
        const std::vector<std::string> &&args):
        m_type(ptype), m_exe(exe), m_args(args)
{
}

container_health_probe::~container_health_probe() {}

const container_mount_info *container_info::mount_by_idx(uint32_t idx) const
{
    if(idx >= m_mounts.size())
    {
        return NULL;
    }

    return &(m_mounts[idx]);
}

const container_mount_info *
container_info::mount_by_source(const std::string &source) const
{
    // note: linear search
    // enable multiline matching to match "^..."
    reflex::Pattern pattern(source, "(?m)");
    for(auto &mntinfo : m_mounts)
    {
        reflex::Matcher matcher(pattern, mntinfo.m_source.c_str());
        if(matcher.find())
        {
            return &mntinfo;
        }
    }
    return NULL;
}

const container_mount_info *
container_info::mount_by_dest(const std::string &dest) const
{
    // note: linear search
    // enable multiline matching to match "^..."
    reflex::Pattern pattern(dest, "(?m)");
    for(auto &mntinfo : m_mounts)
    {
        reflex::Matcher matcher(pattern, mntinfo.m_dest.c_str());
        if(matcher.find())
        {
            return &mntinfo;
        }
    }
    return NULL;
}

container_health_probe::probe_type
container_info::match_health_probe(const std::string &exe,
                                   const std::vector<std::string> &args) const
{

    auto pred = [&](const container_health_probe &p)
    { return (p.m_exe == exe && p.m_args == args); };

    auto match =
            std::find_if(m_health_probes.begin(), m_health_probes.end(), pred);

    if(match == m_health_probes.end())
    {
        return container_health_probe::PT_NONE;
    }

    return match->m_type;
}