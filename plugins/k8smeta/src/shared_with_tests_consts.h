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
#define ASYNC_EVENT_NAME "k8s"
#define ASYNC_EVENT_NAMES                                                      \
    {                                                                          \
        ASYNC_EVENT_NAME                                                       \
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
        PPME_ASYNCEVENT_E, PPME_SYSCALL_EXECVE_19_X, PPME_SYSCALL_EXECVEAT_X,  \
                PPME_SYSCALL_CLONE_20_X, PPME_SYSCALL_FORK_20_X,               \
                PPME_SYSCALL_VFORK_20_X, PPME_SYSCALL_CLONE3_X                 \
    }

#define PARSE_EVENT_SOURCES                                                    \
    {                                                                          \
        "syscall"                                                              \
    }

/////////////////////////
// Table fields
/////////////////////////
#define THREAD_TABLE_NAME "threads"
#define POD_UID_FIELD_NAME "pod_uid"

/////////////////////////
// Proto event reasons
/////////////////////////
#define REASON_CREATE "Create"
#define REASON_UPDATE "Update"
#define REASON_DELETE "Delete"

/////////////////////////
// Generic plugin consts
/////////////////////////
#define PLUGIN_NAME "k8smeta"
#define PLUGIN_VERSION "0.1.0"
#define PLUGIN_DESCRIPTION                                                     \
    "Enrich syscall events with information about the pod that throws them"
#define PLUGIN_CONTACT "github.com/falcosecurity/plugins"
#define PLUGIN_REQUIRED_API_VERSION "3.1.0"

#define REASON_PATH "/reason"
#define KIND_PATH "/kind"
#define UID_PATH "/uid"
#define META_PATH "/meta"
#define NAME_PATH "/name"
#define NAMESPACE_PATH "/namespace"
#define LABELS_PATH "/labels"
#define POD_IP_PATH "/podIP"
#define SPEC_PATH "/spec"
#define STATUS_PATH "/status"
#define REFS_PATH "/refs"
#define VERBOSITY_PATH "/verbosity"
#define HOSTNAME_PATH "/collectorHostname"
#define PORT_PATH "/collectorPort"
#define NODENAME_PATH "/nodeName"
#define CA_CERT_PATH "/caPEMBundle"
