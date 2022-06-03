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

#include <string>
#include <vector>
#include "deps/plugin_info.h"
#include "deps/simdjson.h"

struct json_plugin
{
	std::vector<const char*> m_buf;
	std::vector<std::string> m_values;
	std::string m_last_err;
};

extern "C"
const char* plugin_get_required_api_version()
{
	return PLUGIN_API_VERSION_STR;
}

extern "C"
const char* plugin_get_version()
{
	return "0.4.1";
}

extern "C"
const char* plugin_get_name()
{
	return "json";
}

extern "C"
const char* plugin_get_description()
{
	return "Extract arbitrary fields from events formatted as JSON";
}

extern "C"
const char* plugin_get_contact()
{
	return "github.com/falcosecurity/plugins/";
}

extern "C"
const char* plugin_get_extract_event_sources()
{
	return "[]";
}

extern "C"
const char* plugin_get_fields()
{
	// todo: make this look better
	return "[{\"name\":\"json.value\",\"type\":\"string\",\"isList\":false,\"arg\":{\"isRequired\":true,\"isIndex\":false,\"isKey\":true},\"display\":\"\",\"desc\":\"Extracts a value from a JSON-encoded input. Syntax is json.value[\u003cjson pointer\u003e], where \u003cjson pointer\u003e is a json pointer (see https://datatracker.ietf.org/doc/html/rfc6901)\",\"properties\":null},{\"name\":\"json.obj\",\"type\":\"string\",\"isList\":false,\"arg\":{\"isRequired\":false,\"isIndex\":false,\"isKey\":false},\"display\":\"\",\"desc\":\"The full json message as a text string.\",\"properties\":null},{\"name\":\"json.rawtime\",\"type\":\"string\",\"isList\":false,\"arg\":{\"isRequired\":false,\"isIndex\":false,\"isKey\":false},\"display\":\"\",\"desc\":\"The time of the event, identical to evt.rawtime.\",\"properties\":null},{\"name\":\"jevt.value\",\"type\":\"string\",\"isList\":false,\"arg\":{\"isRequired\":true,\"isIndex\":false,\"isKey\":true},\"display\":\"\",\"desc\":\"Alias for json.value, provided for backwards compatibility.\",\"properties\":null},{\"name\":\"jevt.obj\",\"type\":\"string\",\"isList\":false,\"arg\":{\"isRequired\":false,\"isIndex\":false,\"isKey\":false},\"display\":\"\",\"desc\":\"Alias for json.obj, provided for backwards compatibility.\",\"properties\":null},{\"name\":\"jevt.rawtime\",\"type\":\"string\",\"isList\":false,\"arg\":{\"isRequired\":false,\"isIndex\":false,\"isKey\":false},\"display\":\"\",\"desc\":\"Alias for json.rawtime, provided for backwards compatibility.\",\"properties\":null}]";
}

extern "C"
const char* plugin_get_last_error(ss_plugin_t* s)
{
	return ((json_plugin*) s)->m_last_err.c_str();
}

extern "C"
ss_plugin_t* plugin_init(const char* config, int32_t* rc)
{
	*rc = SS_PLUGIN_SUCCESS;
	return (ss_plugin_t*) new json_plugin();
}

extern "C"
void plugin_destroy(ss_plugin_t* s)
{
	if (s)
	{
		delete ((json_plugin*) s);
	}
}

extern "C"
int32_t plugin_extract_fields(
	ss_plugin_t *s,
	const ss_plugin_event *evt,
	uint32_t num_fields,
	ss_plugin_extract_field *fields)
{
	auto p = ((json_plugin*) s);
    std::string_view sview;
	simdjson::error_code err;
	simdjson::ondemand::document doc;
	simdjson::ondemand::parser parser;
    simdjson::padded_string data((const char*) evt->data, evt->datalen);
	err = parser.iterate(data).get(doc);
	if (err != simdjson::SUCCESS)
	{
        p->m_last_err = simdjson::error_message(err);
        return SS_PLUGIN_FAILURE;
	}

    p->m_buf.resize(num_fields);
	p->m_values.resize(num_fields);
	for (uint32_t i = 0; i < num_fields; i++)
	{
		doc.rewind();
        fields[i].res_len = 0;
		switch(fields[i].field_id)
		{
			case 3: // jevt.value
			case 0: // json.value
				err = doc.at_pointer(fields[i].arg_key).get_string().get(sview);
                if (err != simdjson::SUCCESS)
                {
                    // json pointer is not valid or not present in data
                    p->m_last_err = simdjson::error_message(err);
                    // printf("err %s\n",p->m_last_err.c_str());
                    continue;
                }
				p->m_values[i] = {sview.data(), sview.size()};
                // printf("hey %s\n", p->m_values[i].c_str());
                break;
			case 4: // jevt.obj
			case 1: // json.obj
				p->m_values[i] = (const char*) evt->data;
				break;
			case 5: // jevt.rawtime
			case 2: // json.rawtime
				p->m_values[i] = std::to_string(evt->ts);
				break;
			default:
				p->m_last_err = "unknown field: " + std::string(fields[i].field);
				return SS_PLUGIN_FAILURE;
		}
		p->m_buf[i] = p->m_values[i].c_str();
		fields[i].res.str = &p->m_buf[i];
		fields[i].res_len = 1;
	}
	return SS_PLUGIN_SUCCESS;
}