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

#include <falcosecurity/sdk.h>

// Sinsp events used in the plugin
using _et = falcosecurity::event_type;
constexpr auto PPME_ASYNCEVENT_E = (_et)402;
constexpr auto PPME_CONTAINER_E = (_et)228;
constexpr auto PPME_CONTAINER_JSON_E = (_et)272;
constexpr auto PPME_CONTAINER_JSON_2_E = (_et)324;
constexpr auto PPME_SYSCALL_CLONE_20_X = (_et)223;
constexpr auto PPME_SYSCALL_CLONE3_X = (_et)335;
constexpr auto PPME_SYSCALL_FORK_20_X = (_et)225;
constexpr auto PPME_SYSCALL_VFORK_20_X = (_et)227;
constexpr auto PPME_SYSCALL_EXECVE_16_X = (_et)231;
constexpr auto PPME_SYSCALL_EXECVE_17_X = (_et)283;
constexpr auto PPME_SYSCALL_EXECVE_18_X = (_et)289;
constexpr auto PPME_SYSCALL_EXECVE_19_X = (_et)293;
constexpr auto PPME_SYSCALL_EXECVEAT_X = (_et)331;
constexpr auto PPME_SYSCALL_CHROOT_X = (_et)267;

#define SHORT_ID_LEN 12