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
 * in C++. It uses the C++ sdk ../../sdk/cpp/falcosecurity_plugin.h
 * and implements classes that derive from
 * falcosecurity::source_plugin and falcosecurity::plugin_instance. */

#include <string>
#include <stdio.h>
#include <stdlib.h>

#include "nlohmann/json.hpp"

#include <falcosecurity_plugin.h>

using json = nlohmann::json;

class dummy_plugin : public falcosecurity::source_plugin {
public:
	dummy_plugin();
	virtual ~dummy_plugin();

	// All of these are from falcosecurity::source_plugin_iface.
	void get_info(falcosecurity::plugin_info &info) override;
	ss_plugin_rc init(const char *config) override;
	void destroy() override;
	falcosecurity::plugin_instance *create_instance(falcosecurity::source_plugin &plugin) override;
	std::string event_to_string(const uint8_t *data, uint32_t datalen) override;
	bool extract_str(const ss_plugin_event &evt, const std::string &field, const std::string &arg, std::string &extract_val) override;
	bool extract_u64(const ss_plugin_event &evt, const std::string &field, const std::string &arg, uint64_t &extract_val) override;

	// Return the configured jitter.
	uint64_t jitter();

private:
	// A copy of the config provided to init()
	std::string m_config;

	// This reflects potential internal state for the plugin. In
	// this case, the plugin is configured with a jitter (e.g. a
	// random amount to add to the sample with each call to next().
	uint64_t m_jitter;
};

class dummy_instance : public falcosecurity::plugin_instance {
public:
	dummy_instance(dummy_plugin &plugin);
	virtual ~dummy_instance();

	// All of these are from falcosecurity::plugin_instance_iface.
	ss_plugin_rc open(const char *params) override;
	void close() override;
	ss_plugin_rc next(falcosecurity::plugin_event &evt) override;

private:
	// The plugin that created this instance
	dummy_plugin &m_plugin;

	// All of these reflect potential internal state for the
	// instance.

	// Copy of the init params from plugin_open()
	std::string m_params;

	// The number of events to return before EOF
	uint64_t m_max_events;

	// A count of events returned. Used to count against m_max_events
	uint64_t m_counter;

	// A semi-random numeric value, derived from this value and
	// jitter. This is put in every event as the data property.
	uint64_t m_sample;
};

dummy_plugin::dummy_plugin()
	: m_jitter(10)
{
};

dummy_plugin::~dummy_plugin()
{
};


void dummy_plugin::get_info(falcosecurity::plugin_info &info)
{
	info.name = "dummy_c";
	info.description = "Reference plugin for educational purposes";
	info.contact = "github.com/falcosecurity/plugins";
	info.version = "0.1.0";
	info.event_source = "dummy";
	info.fields = {
		{FTYPE_UINT64, "dummy.divisible", true, "Return 1 if the value is divisible by the provided divisor, 0 otherwise"},
		{FTYPE_UINT64, "dummy.value", false, "The sample value in the event"},
		{FTYPE_STRING, "dummy.strvalue", false, "The sample value in the event, as a string"}
	};
}

ss_plugin_rc dummy_plugin::init(const char *config)
{
	m_config = config;

	// Config is optional. In this case defaults are used.
	if(m_config == "" || m_config == "{}")
	{
		return SS_PLUGIN_SUCCESS;
	}

	json obj;

	try {
		obj = json::parse(m_config);
	}
	catch (std::exception &e)
	{
		// No need to call set_last_error() here as the plugin
		// struct doesn't exist to the framework yet.
		return SS_PLUGIN_FAILURE;
	}

	auto it = obj.find("jitter");

	if(it == obj.end())
	{
		// No need to call set_last_error() here as the plugin
		// struct doesn't exist to the framework yet.
		return SS_PLUGIN_FAILURE;
	}

	m_jitter = *it;

	return SS_PLUGIN_SUCCESS;
}

void dummy_plugin::destroy()
{
}

falcosecurity::plugin_instance *dummy_plugin::create_instance(falcosecurity::source_plugin &plugin)
{
	return new dummy_instance((dummy_plugin &) plugin);

}

std::string dummy_plugin::event_to_string(const uint8_t *data, uint32_t datalen)
{
	// The string representation of an event is a json object with the sample
	std::string rep = "{\"sample\": ";
	rep.append((char *) data, datalen);
	rep += "}";

	return rep;
}

bool dummy_plugin::extract_str(const ss_plugin_event &evt, const std::string &field, const std::string &arg, std::string &extract_val)
{
	if (field == "dummy.strvalue")
	{
		extract_val.assign((char *) evt.data, evt.datalen);
		return true;
	}

	return false;
}

bool dummy_plugin::extract_u64(const ss_plugin_event &evt, const std::string &field, const std::string &arg, uint64_t &extract_val)
{
	std::string sample((char *) evt.data, evt.datalen);
	uint64_t isample = std::stoi(sample);

	if(field == "dummy.divisible")
	{
		uint64_t divisor = std::stoi(arg);
		if ((isample % divisor) == 0)
		{
			extract_val = 1;
		}
		else
		{
			extract_val = 0;
		}

		return true;
	}
	else if (field == "dummy.value")
	{
		extract_val = isample;

		return true;
	}

	return false;
}

uint64_t dummy_plugin::jitter()
{
	return m_jitter;
}

dummy_instance::dummy_instance(dummy_plugin &plugin)
	: m_plugin(plugin)
{
}

dummy_instance::~dummy_instance()
{
}

ss_plugin_rc dummy_instance::open(const char *params)
{
	m_params = params;

	// Params are optional. In this case defaults are used.
	if(m_params == "" || m_params == "{}")
	{
		return SS_PLUGIN_SUCCESS;
	}

	json obj;

	try {
		obj = json::parse(m_params);
	}
	catch (std::exception &e)
	{
		std::string errstr = std::string("Params ") + m_params + " could not be parsed: " + e.what();
		m_plugin.set_last_error(errstr);
		return SS_PLUGIN_FAILURE;
	}

	auto start_it = obj.find("start");
	if(start_it == obj.end())
	{
		std::string errstr = std::string("Params ") + m_params + " did not contain start property";
		m_plugin.set_last_error(errstr);
		return SS_PLUGIN_FAILURE;
	}

	auto max_events_it = obj.find("maxEvents");
	if(max_events_it == obj.end())
	{
		std::string errstr = std::string("Params ") + m_params + " did not contain maxEvents property";
		m_plugin.set_last_error(errstr);
		return SS_PLUGIN_FAILURE;
	}

	m_counter = 0;
	m_max_events = *max_events_it;
	m_sample = *start_it;

	return SS_PLUGIN_SUCCESS;
}

void dummy_instance::close()
{
}

ss_plugin_rc dummy_instance::next(falcosecurity::plugin_event &evt)
{
	m_counter++;

	if(m_counter > m_max_events)
	{
		return SS_PLUGIN_EOF;
	}

	// Increment sample by 1, also add a jitter of [0:jitter]
	m_sample = m_sample + 1 + (random() % (m_plugin.jitter() + 1));

	// The event payload is simply the sample, as a string
	std::string payload = std::to_string(m_sample);

	// Note that evtnum is not set, as event numbers are
	// assigned by the plugin framework.
	evt.data.assign(payload.begin(), payload.end());

	// Let the plugin framework assign timestamps
	evt.ts = (uint64_t) -1;

	return SS_PLUGIN_SUCCESS;
}

// This macro creates the plugin_xxx functions that comprise the
// source plugin API. It creates dummy_plugin and dummy_instance
// objects as needed and translates the plugin API calls into the
// methods in falcosecurity::source_plugin_iface and
// falcosecurity::plugin_instance_iface.
GEN_SOURCE_PLUGIN_API_HOOKS(dummy_plugin, dummy_instance)
