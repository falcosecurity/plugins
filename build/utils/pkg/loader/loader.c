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

#include <dlfcn.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "loader.h"

static void* getsym(uintptr_t handle, const char* name, char* err)
{
	void *ret = dlsym((void*) handle, name);
	if(ret == NULL)
	{
        strcpy(err, "can't resolve dynamic library symbol: ");
        strcat(err, name);
	}
	return ret;
}

static void concaterr(char* err, const char* othererr)
{
    char tmp[PLUGIN_LOADER_MAX_ERRLEN];
    strncpy(tmp, othererr, PLUGIN_LOADER_MAX_ERRLEN);
    strncat(tmp, err, PLUGIN_LOADER_MAX_ERRLEN - 1);
    strncpy(err, tmp, PLUGIN_LOADER_MAX_ERRLEN);
}

plugin_loader_library_t* plugin_loader_load(const char* path, char* err)
{
    // open library
    plugin_loader_library_t* ret = (plugin_loader_library_t*) malloc (sizeof(plugin_loader_library_t));
    ret->handle = (uintptr_t) dlopen(path, RTLD_NOW | RTLD_GLOBAL);
	if ((void*) ret->handle == NULL)
    {
        strcpy(err, (const char*) dlerror());
        concaterr(err, "can't load plugin dynamic library: ");
        free(ret);
        return NULL;
	}

    // load library symbols
    memset(&ret->api, 0, sizeof(plugin_api));
    *(void **)(&(ret->api.get_required_api_version)) = getsym(ret->handle, "plugin_get_required_api_version", err);
    *(void **)(&(ret->api.get_version)) = getsym(ret->handle, "plugin_get_version", err);
    *(void **)(&(ret->api.get_last_error)) = getsym(ret->handle, "plugin_get_last_error", err);
    *(void **)(&(ret->api.get_name)) = getsym(ret->handle, "plugin_get_name", err);
    *(void **)(&(ret->api.get_description)) = getsym(ret->handle, "plugin_get_description", err);
    *(void **)(&(ret->api.get_contact)) = getsym(ret->handle, "plugin_get_contact", err);
    *(void **)(&(ret->api.get_init_schema)) = getsym(ret->handle, "plugin_get_init_schema", err);
    *(void **)(&(ret->api.init)) = getsym(ret->handle, "plugin_init", err);
    *(void **)(&(ret->api.destroy)) = getsym(ret->handle, "plugin_destroy", err);
    *(void **)(&(ret->api.get_id)) = getsym(ret->handle, "plugin_get_id", err);
    *(void **)(&(ret->api.get_event_source)) = getsym(ret->handle, "plugin_get_event_source", err);
    *(void **)(&(ret->api.open)) = getsym(ret->handle, "plugin_open", err);
    *(void **)(&(ret->api.close)) = getsym(ret->handle, "plugin_close", err);
    *(void **)(&(ret->api.next_batch)) = getsym(ret->handle, "plugin_next_batch", err);
    *(void **)(&(ret->api.get_progress)) = getsym(ret->handle, "plugin_get_progress", err);
    *(void **)(&(ret->api.list_open_params)) = getsym(ret->handle, "plugin_list_open_params", err);
    *(void **)(&(ret->api.event_to_string)) = getsym(ret->handle, "plugin_event_to_string", err);
    *(void **)(&(ret->api.get_fields)) = getsym(ret->handle, "plugin_get_fields", err);
    *(void **)(&(ret->api.extract_fields)) = getsym(ret->handle, "plugin_extract_fields", err);
    *(void **)(&(ret->api.get_extract_event_sources)) = getsym(ret->handle, "plugin_get_extract_event_sources", err);

    // check required symbols
    bool has_required_symbols = ret->api.get_required_api_version
        && ret->api.get_version
        && ret->api.get_last_error
        && ret->api.get_name
        && ret->api.get_description
        && ret->api.get_contact
        && ret->api.get_init_schema
        && ret->api.init; 
    if (!has_required_symbols)
    {
        concaterr(err, "plugin does not implement required symbols: ");
        free(ret);
        return NULL;
	}
    
    // check event sourcing capability
    ret->has_sourcing_capability = ret->api.get_id
        && ret->api.get_event_source
        && ret->api.open
        && ret->api.close
        && ret->api.next_batch;

    // check field extraction capability
    ret->has_extraction_capability = ret->api.get_fields
        && ret->api.extract_fields;

    // check capabilities validity
    if (!ret->has_sourcing_capability && !ret->has_extraction_capability)
    {
        strcpy(err, "plugin implements no capability");
        free(ret);
        return NULL;
	}
    
    strcpy(err, "");
	return ret;
}

void plugin_loader_unload(plugin_loader_library_t* h)
{
    if (h)
    {
        if (h->handle)
        {
            dlclose((void*) h->handle);
        }
        free(h);
    }
}
