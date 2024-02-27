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

/////////////////////////
// Generic plugin consts
/////////////////////////

#define PLUGIN_NAME "anomalydetection"
#define PLUGIN_VERSION "0.1.0"
#define PLUGIN_DESCRIPTION "Enhance {syscall} event analysis by incorporating anomaly detection estimates for probabilistic filtering."
#define PLUGIN_CONTACT "github.com/falcosecurity/plugins"
#define PLUGIN_REQUIRED_API_VERSION "3.1.0"
#define PLUGIN_LOG_PREFIX "[anomalydetection]"

///////////////////////////
// Thread Table (libsinsp)
///////////////////////////

#define THREAD_TABLE_NAME "threads"
