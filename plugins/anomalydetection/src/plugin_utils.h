// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#pragma once

#include "plugin_sinsp_filterchecks.h"
#include "plugin_consts.h"

#include <falcosecurity/sdk.h>

#include <regex>
#include <unordered_set>

typedef struct plugin_sinsp_filterchecks_field
{
    plugin_sinsp_filterchecks::check_type id;
    std::int32_t argid;
    std::string argname;
}plugin_sinsp_filterchecks_field;

namespace plugin_anomalydetection::utils
{
    // Adopter from libs, custom hand-rolled for performance reasons
    std::string concatenate_paths(std::string_view path1, std::string_view path2);

    // Temporary workaround; not as robust as libsinsp/eventformatter; 
    // ideally the plugin API exposes more libsinsp functionality in the near-term
    //
    // No need for performance optimization atm as the typical use case is to have less than 3-8 sketches
    const std::vector<plugin_sinsp_filterchecks_field> get_profile_fields(const std::string& behavior_profile);

    inline void log_error(std::string err_mess)
    {
        printf("%s %s\n", PLUGIN_LOG_PREFIX, err_mess.c_str());
    }

} // plugin_anomalydetection::utils