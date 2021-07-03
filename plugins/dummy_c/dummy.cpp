/*
Copyright (C) 2021 The Falco Authors.

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

/* Reference "dummy" plugin, similar to the dummy plugin, but written
 * in C */

#include <string>
#include <stdio.h>
#include <stdlib.h>

#include "nlohmann/json.hpp"

#include <plugin_info.h>

using json = nlohmann::json;

static const char *pl_required_api_version = "1.0.0";
static uint32_t    pl_type                 = TYPE_SOURCE_PLUGIN;
static uint32_t    pl_id                   = 4;
static const char *pl_name                 = "dummy_c";
static const char *pl_desc                 = "Reference plugin for educational purposes";
static const char *pl_contact              = "github.com/falcosecurity/plugins";
static const char *pl_version              = "1.0.0";
static const char *pl_event_source         = "dummy";
static const char *pl_fields               = R"(
[{"type": "uint64", "name": "dummy.divisible", "argRequired": true, "desc": "Return 1 if the value is divisible by the provided divisor, 0 otherwise"},
{"type": "uint64", "name": "dummy.value", "desc": "The sample value in the event"},
{"type": "string", "name": "dummy.strvalue", "desc": "The sample value in the event, as a string"}])";

// This struct represents the state of a plugin. Just has a placeholder string value.
typedef struct plugin_state
{
	// A copy of the config provided to plugin_init()
	std::string config;

	// When a function results in an error, this is set and can be
	// retrieved in plugin_get_last_error().
	std::string last_error;

	// This reflects potential internal state for the plugin. In
	// this case, the plugin is configured with a jitter (e.g. a
	// random amount to add to the sample with each call to Next()
	uint64_t jitter;

} plugin_state;

typedef struct instance_state
{
	// Copy of the init params from plugin_open()
	std::string params;

	// The number of events to return before EOF
	uint64_t max_events;

	// A count of events returned. This is put in every event as
	// the evtnum property.
	uint64_t counter;

	// A semi-random numeric value, derived from the counter and
	// jitter. This is put in every event as the data property.
	uint64_t sample;
} instance_state;

extern "C"
char* plugin_get_required_api_version()
{
	printf("[%s] plugin_get_required_api_version\n", pl_name);
	return strdup(pl_required_api_version);
}

extern "C"
uint32_t plugin_get_type()
{
	printf("[%s] plugin_get_type\n", pl_name);
	return pl_type;
}

extern "C"
uint32_t plugin_get_id()
{
	printf("[%s] plugin_get_id\n", pl_name);
	return pl_id;
}

extern "C"
char* plugin_get_name()
{
	printf("[%s] plugin_get_name\n", pl_name);
	return strdup(pl_name);
}

extern "C"
char* plugin_get_description()
{
	printf("[%s] plugin_get_description\n", pl_name);
	return strdup(pl_desc);
}

extern "C"
char* plugin_get_contact()
{
	printf("[%s] plugin_get_contact\n", pl_name);
	return strdup(pl_contact);
}

extern "C"
char* plugin_get_version()
{
	printf("[%s] plugin_get_version\n", pl_name);
	return strdup(pl_version);
}

extern "C"
char* plugin_get_event_source()
{
	printf("[%s] plugin_get_event_source\n", pl_name);
	return strdup(pl_event_source);
}

extern "C"
char* plugin_get_fields()
{
	printf("[%s] plugin_get_fields\n", pl_name);
	return strdup(pl_fields);
}

extern "C"
char* plugin_get_last_error(ss_plugin_t* s)
{
	printf("[%s] plugin_get_last_error\n", pl_name);

	plugin_state *state = (plugin_state *) s;

	if(!state->last_error.empty())
	{
		char *ret = strdup(state->last_error.c_str());
		state->last_error = "";
		return ret;
	}

	return NULL;
}

extern "C"
ss_plugin_t* plugin_init(char* config, int32_t* rc)
{
	printf("[%s] plugin_init config=%s\n", pl_name, config);

	json obj;

	try {
		obj = json::parse(config);
	}
	catch (std::exception &e)
	{
		return NULL;
	}

	auto it = obj.find("jitter");

	if(it == obj.end())
	{
		return NULL;
	}

	// Note: Using new/delete is okay, as long as the plugin
	// framework is not deleting the memory.
	plugin_state *ret = new plugin_state();
	ret->config = config;
	ret->last_error = "";
	ret->jitter = *it;

	*rc = SS_PLUGIN_SUCCESS;

	return ret;
}

extern "C"
void plugin_destroy(ss_plugin_t* s)
{
	printf("[%s] plugin_destroy\n", pl_name);

	plugin_state *ps = (plugin_state *) s;

	delete(ps);
}

extern "C"
ss_instance_t* plugin_open(ss_plugin_t* s, char* params, int32_t* rc)
{
	printf("[%s] plugin_open params=%s\n", pl_name, params);

	plugin_state *ps = (plugin_state *) s;

	json obj;

	try {
		obj = json::parse(params);
	}
	catch (std::exception &e)
	{
		ps->last_error = std::string("Params ") + params + " could not be parsed: " + e.what();
		*rc = SS_PLUGIN_FAILURE;
		return NULL;
	}

	auto start_it = obj.find("start");
	if(start_it == obj.end())
	{
		ps->last_error = std::string("Params ") + params + " did not contain start property";
		*rc = SS_PLUGIN_FAILURE;
		return NULL;
	}

	auto max_events_it = obj.find("maxEvents");
	if(max_events_it == obj.end())
	{
		ps->last_error = std::string("Params ") + params + " did not contain maxEvents property";
		*rc = SS_PLUGIN_FAILURE;
		return NULL;
	}

	// Note: Using new/delete is okay, as long as the plugin
	// framework is not deleting the memory.
	instance_state *ret = new instance_state();
	ret->params = params;
	ret->counter = 0;
	ret->max_events = *max_events_it;
	ret->sample = *start_it;

	*rc = SS_PLUGIN_SUCCESS;

	return ret;
}

extern "C"
void plugin_close(ss_plugin_t* s, ss_instance_t* i)
{
	printf("[%s] plugin_close\n", pl_name);

	instance_state *istate = (instance_state *) i;

	delete(istate);
}

extern "C"
int32_t plugin_next(ss_plugin_t* s, ss_instance_t* i, ss_plugin_event **evt)
{
	printf("[%s] plugin_next\n", pl_name);

	plugin_state *state = (plugin_state *) s;
	instance_state *istate = (instance_state *) i;

	istate->counter++;

	if(istate->counter > istate->max_events)
	{
		return SS_PLUGIN_EOF;
	}

	// Increment sample by 1, also add a jitter of [0:jitter]
	istate->sample = istate->sample + 1 + (random() % (state->jitter + 1));

	// The event payload is simply the sample, as a string
	std::string payload = std::to_string(istate->sample);

	struct ss_plugin_event *ret = (struct ss_plugin_event *) malloc(sizeof(ss_plugin_event));

	ret->evtnum = istate->counter;
	ret->data = (uint8_t *) strdup(payload.c_str());
	ret->datalen = payload.size();

	// Let the plugin framework assign timestamps
	ret->ts = (uint64_t) -1;

	*evt = ret;

	return SS_PLUGIN_SUCCESS;
}

// This plugin does not implement plugin_next_batch, due to the lower
// overhead of calling C functions from the plugin framework compared
// to calling Go functions.

extern "C"
char *plugin_event_to_string(ss_plugin_t *s, const uint8_t *data, uint32_t datalen)
{
	printf("[%s] plugin_event_to_string\n", pl_name);

	plugin_state *state = (plugin_state *) s;

	// The string representation of an event is a json object with the sample
	std::string rep = "{\"sample\": ";
	rep.append((char *) data, datalen);
	rep += "}";

	return strdup(rep.c_str());
}

extern "C"
int32_t plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)
{
	printf("[%s] plugin_extract_fields\n", pl_name);

	std::string sample((char *) evt->data, evt->datalen);
	uint64_t isample = std::stoi(sample);

	for(uint32_t i=0; i < num_fields; i++)
	{
		ss_plugin_extract_field *field = &(fields[i]);

		if(strcmp(field->field, "dummy.divisible") == 0)
		{
			field->field_present = 1;

			uint64_t divisor = std::stoi(std::string(field->arg));
			if ((isample % divisor) == 0)
			{
				field->res_u64 = 1;
			}
			else
			{
				field->res_u64 = 0;
			}
		}
		else if (strcmp(field->field, "dummy.value") == 0)
		{
			field->field_present = 1;
			field->res_u64 = isample;
		}
		else if (strcmp(field->field, "dummy.strvalue") == 0)
		{
			field->field_present = 1;
			field->res_str = strdup(sample.c_str());
		}
		else
		{
			field->field_present = 0;
		}
	}

	return SS_PLUGIN_SUCCESS;
}
