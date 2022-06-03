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
#define MAX_KEY_LEN     4096

#include <string>
#include <string.h>
#include <vector>
#include "deps/plugin_info.h"
#include "deps/zzzjson.h"

struct json_plugin
{
	uint32_t m_last_evt_num;
	zj::Value *m_last_doc;
	bool m_valid_doc;
	std::vector<const char*> m_buf;
	std::vector<std::string> m_values;
	std::string m_last_err;
};

static bool json_ptr_str(zj::Value *node, const char* ptr, std::string& out)
{
	char c;
	char key[MAX_KEY_LEN];
	bool key_num;
	size_t key_len;

	if (!ptr)
	{
		return false;
	}

	while (*ptr)
	{
		auto type = zj::Type(node);
		if (!type)
		{
			return false;
		}

		// extract pointer key
		key_len = 0;
		key_num = true;
		if (*ptr == '/')
		{
			ptr++;
		}
		while (key_len < MAX_KEY_LEN && *ptr && *ptr != '/')
		{
			c = *ptr++;
			if (c == '~')
			{
				switch (*ptr)
				{
					case '0':
						c = '~';
						break;
					case '1':
						c = '/';
						break;
					default:
						// todo: return an error too
						return false;
				}
				ptr++;
			}
			if (!isdigit(c))
			{
				key_num = false;
			}
			key[key_len++] = c;
		}
		key[key_len] = '\0';

		// extract next node
		if (key_len > 0)
		{
			zj::Value *key_node = node;
			switch (*type)
			{
				case zj::JSONTypeArray:
				{
					if (key_num)
					{
						auto idx = atoi(key);
						zj::Value *next = zj::Begin(node);
						while (next != 0)
						{
							if (--idx == 0)
							{
								key_node = next;
								break;
							}
							next = zj::Next(next);
						}
					}
					break;
				}
				case zj::JSONTypeObject:
				{
					zj::Size len;
					zj::Value *next = zj::Begin(node);
					while (next != 0)
					{
						auto k = zj::GetKeyFast(next, &len);
						if (len == key_len && !strncmp(key, k, len))
						{
							key_node = next;
							break;
						}
						next = zj::Next(next);
					}
					break;
				}
				case zj::JSONTypeBool:
				case zj::JSONTypeNumber:	
				case zj::JSONTypeString:
				case zj::JSONTypeNull:
					break;
			}

			if (node == key_node)
			{
				return false;
			}
			node = key_node;
		}
	}

	auto type = zj::Type(node);
	if (type)
	{
		switch (*type)
		{
			case zj::JSONTypeBool:
			{
				out = std::to_string(*zj::GetBool(node));
				return true;
			}
			case zj::JSONTypeNumber:
			{
				zj::Size len;
				const char* str = zj::GetNumFast(node, &len);
				out = std::string(str, len);
				return true;
			}
			case zj::JSONTypeString:
			{
				zj::Size len;
				const char* str = zj::GetStrFast(node, &len);
				out = std::string(str, len);
				return true;
			}
			case zj::JSONTypeArray:
			case zj::JSONTypeObject:
			case zj::JSONTypeNull:
				break;
		}
	}

	return false;
}

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
	auto ret = new json_plugin();
	ret->m_last_doc = nullptr;
	ret->m_last_evt_num = 0;
	return (ss_plugin_t*) ret;
}

extern "C"
void plugin_destroy(ss_plugin_t* s)
{
	if (s)
	{
		auto p = ((json_plugin*) s);
		if (p->m_last_doc)
		{
			zj::ReleaseAllocator(p->m_last_doc->A);
		}
		delete p;
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
	if (evt->evtnum != p->m_last_evt_num)
	{
		if (p->m_last_doc)
		{
			zj::ReleaseAllocator(p->m_last_doc->A);
		}
		p->m_last_doc = zj::NewValue(zj::NewAllocator());
		p->m_valid_doc = zj::ParseFast(p->m_last_doc, (const char*) evt->data);
		p->m_last_evt_num = evt->evtnum;
	}
    p->m_buf.resize(num_fields);
	p->m_values.resize(num_fields);
	for (uint32_t i = 0; i < num_fields; i++)
	{
        fields[i].res_len = 0;
		if (p->m_valid_doc )
		{
			switch(fields[i].field_id)
			{
				case 3: // jevt.value
				case 0: // json.value
					if (!json_ptr_str(p->m_last_doc, fields[i].arg_key, p->m_values[i]))
					{
						continue;
					}
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
	}

	return SS_PLUGIN_SUCCESS;
}