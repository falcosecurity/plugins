/*
Copyright (C) 2022 The Falco Authors.

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

#include "plugin_info.h"
#include <stdint.h>

#define PLUGIN_LOADER_MAX_ERRLEN    2048

typedef struct plugin_loader_library_t
{
    uintptr_t handle;
    plugin_api api;
    bool has_sourcing_capability;
    bool has_extraction_capability;
} plugin_loader_library_t;

plugin_loader_library_t* plugin_loader_load(const char* path, char* err);
void plugin_loader_unload(plugin_loader_library_t* h);
