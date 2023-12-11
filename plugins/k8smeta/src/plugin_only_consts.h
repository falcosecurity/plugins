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

#pragma once

/// todo!: According to perf tests we could compile out some logs
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE

#include <falcosecurity/sdk.h>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>

// Regex to extract the pod uid from cgroups
#define RGX_POD                                                                \
    "(pod[a-z0-9]{8}[-_][a-z0-9]{4}[-_][a-z0-9]{4}[-_][a-z0-9]{4}[-_][a-z0-9]" \
    "{12})"

// Sinsp events used in the plugin
using _et = falcosecurity::event_type;
constexpr auto PPME_ASYNCEVENT_E = (_et)402;
constexpr auto PPME_SYSCALL_CLONE_20_X = (_et)223;
constexpr auto PPME_SYSCALL_CLONE3_X = (_et)335;
constexpr auto PPME_SYSCALL_FORK_20_X = (_et)225;
constexpr auto PPME_SYSCALL_VFORK_20_X = (_et)227;
constexpr auto PPME_SYSCALL_EXECVE_19_X = (_et)293;
constexpr auto PPME_SYSCALL_EXECVEAT_X = (_et)331;

// Data associated to sinsp events used in the plugin
#define EXECVE_CLONE_RES_PARAM_IDX 0
#define EXECVE_CLONE_CGROUP_PARAM_IDX 14
