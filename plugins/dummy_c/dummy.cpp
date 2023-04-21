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

#include "dummy.h"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

void dummy_plugin::info(falcosecurity::plugin::information& out) const 
{
    out.name = "dummy_c";
	out.description = "Reference plugin for educational purposes";
    out.contact = "https://github.com/falcosecurity/plugins";
    out.version = "0.2.3";
}

bool dummy_plugin::init(const std::string& config)
{
    m_config = config;
	// Config is optional. In this case defaults are used.
	if(m_config.empty() || m_config.compare("{}"))
	{
		return true;
	}

	json obj;
	try {
		obj = json::parse(m_config);
	}catch(std::exception e){
		return false;
	}

	auto it = obj.find("jitter");
	if(it != obj.end())
	{
        m_jitter = *it;
	}

	auto max_events = obj.find("maxEvents");
	if(max_events != obj.end())
	{
        m_max_events = *max_events;
	}

	return true;
}

void dummy_plugin::last_error(std::string& out) const
{
    out.clear();
}

void dummy_plugin::fields(std::vector<falcosecurity::field_extractor::field>& out) const 
{
    falcosecurity::field_extractor::field f;
    f.name = "dummy.divisible";
    f.type = FTYPE_UINT64;
    f.display = "Return 1 if the value is divisible by the provided divisor, 0 otherwise";
    f.description = "Return 1 if the value is divisible by the provided divisor, 0 otherwise";
    f.arg.index = true;
    out.clear();
    out.push_back(f);

    f.name = "dummy.value";
    f.type = FTYPE_UINT64;
    f.display = "The sample value in the event";
    f.description = "The sample value in the event";
    out.push_back(f);

    f.name = "dummy.strvalue";
    f.type = FTYPE_STRING;
    f.display = "The sample value in the event, as a string";
    f.description = "The sample value in the event, as a string";
    out.push_back(f);
}

bool dummy_plugin::extract(const ss_plugin_event* evt, ss_plugin_extract_field* field) 
{
    uint64_t divisor;
    uint64_t res = 0;
    switch (field->field_id) {
        case 0: //dummy.divisible
             divisor = field->arg_index;
            if ((m_sample % divisor) == 0)
            {
                res = 1;
            }

            field->res.u64 = &res;
            field->res_len = 1;
            return true;
        case 1: //dummy.value
            field->res.u64 = (uint64_t*) evt->data;
            field->res_len = 1;
            return true;
        case 2: //dummy.strvalue
            // The event payload is simply the sample, as a string
            std::string payload = "__"+std::to_string(m_sample)+"__";
            const char* payload_ptr = payload.c_str();

            field->res.str = (const char**) &payload_ptr;
            field->res_len = 1;

            return true;
    }
    return false;
}

uint32_t dummy_plugin::id() const 
{
    return 999;
}

void dummy_plugin::event_source(std::string& out) const 
{
    out = "dummy_c";
}

std::unique_ptr<falcosecurity::event_sourcer::instance> dummy_plugin::open(const std::string& params) 
{
    if(!params.empty()){
        m_max_events = std::stoi(params);
    }
    return std::unique_ptr<falcosecurity::event_sourcer::instance>(new dummy_instance(m_max_events, &m_sample));
}

ss_plugin_rc dummy_instance::next(const falcosecurity::event_sourcer* p, ss_plugin_event* evt) 
{
    m_count++;

    if(m_count > m_max_events)
    {
        return SS_PLUGIN_EOF;
    }

    // Increment sample by 1, also add a jitter of [0:jitter]
    *m_sample = *m_sample + 1 + (random() % (m_jitter + 1));

    evt->data = (uint8_t*) m_sample;
    evt->datalen = sizeof(uint64_t);

    return SS_PLUGIN_SUCCESS;
}
