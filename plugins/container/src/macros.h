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

// This consts file is shared between the plugin and tests

/////////////////////////
// Async capability
/////////////////////////
// This is the same name as the pre-existing container event
// (PPME_CONTAINER_JSON_E) to avoid touching the rules (eg:
// https://github.com/falcosecurity/rules/blob/d8415c1bc13e6607b477360afda3dae66d2abd16/rules/falco-incubating_rules.yaml#L300)
#define ASYNC_EVENT_NAME_ADDED "container"
#define ASYNC_EVENT_NAME_REMOVED                                               \
    "container_removed" // the removed event is a whole new event and is only
                        // generated for listeners engines (by the go-worker).
#define ASYNC_EVENT_NAMES                                                      \
    {                                                                          \
        ASYNC_EVENT_NAME_ADDED, ASYNC_EVENT_NAME_REMOVED                       \
    }
#define ASYNC_EVENT_SOURCES                                                    \
    {                                                                          \
        "syscall"                                                              \
    }

/////////////////////////
// Extract capability
/////////////////////////
#define EXTRACT_EVENT_NAMES                                                    \
    {                                                                          \
        ""                                                                     \
    }

#define EXTRACT_EVENT_SOURCES                                                  \
    {                                                                          \
        "syscall"                                                              \
    }

/////////////////////////
// Parse capability
/////////////////////////
#define PARSE_EVENT_CODES                                                      \
    {                                                                          \
        PPME_ASYNCEVENT_E, PPME_CONTAINER_E, PPME_CONTAINER_JSON_E,            \
                PPME_CONTAINER_JSON_2_E, PPME_SYSCALL_CLONE_20_X,              \
                PPME_SYSCALL_FORK_20_X, PPME_SYSCALL_VFORK_20_X,               \
                PPME_SYSCALL_CLONE3_X, PPME_SYSCALL_EXECVE_16_X,               \
                PPME_SYSCALL_EXECVE_17_X, PPME_SYSCALL_EXECVE_18_X,            \
                PPME_SYSCALL_EXECVE_19_X, PPME_SYSCALL_EXECVEAT_X,             \
                PPME_SYSCALL_CHROOT_X                                          \
    }

#define PARSE_EVENT_SOURCES                                                    \
    {                                                                          \
        "syscall"                                                              \
    }

/////////////////////////
// Table fields
/////////////////////////
#define THREAD_TABLE_NAME "threads"
#define CGROUPS_TABLE_NAME "cgroups"
#define CGROUP_SECOND_FIELD_NAME "second"
#define CONTAINER_ID_FIELD_NAME "container_id"
#define PIDNS_INIT_START_TS_FIELD_NAME "pidns_init_start_ts"
#define CATEGORY_FIELD_NAME "category"
#define VPID_FIELD_NAME "vpid"
#define PTID_FIELD_NAME "ptid"

/////////////////////////
// Metrics
/////////////////////////
#define METRIC_N_CONTAINERS "n_containers"
#define METRIC_N_MISSING "n_missing_container_images"

/////////////////////////
// Generic plugin consts
/////////////////////////
#define PLUGIN_NAME "container"
#define PLUGIN_VERSION "0.1.0"
#define PLUGIN_DESCRIPTION                                                     \
    "Enrich syscall events with metadata from the container"
#define PLUGIN_CONTACT "github.com/falcosecurity/plugins"
#define PLUGIN_REQUIRED_API_VERSION "3.10.0"