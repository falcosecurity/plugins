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

#pragma once

#include <list>
#include <memory>
#include <set>
#include <sstream>
#include <string>

#include "plugin_info.h"

namespace falcosecurity {

// A friendlier view into a description of a field. It's used to pass
// back a full description of fields to the framework in
// plugin_get_fields().
typedef struct plugin_field {
	ss_plugin_field_type ftype;
	std::string name;
	bool arg_required;
	std::string description;
} plugin_field;

std::ostream& operator<< (std::ostream &os, plugin_field const &f)
{
	os << "{";
	os << "\"type\":\"" << (f.ftype == FTYPE_UINT64 ? "uint64" : "string") << "\",";
	os << "\"name\":\"" << f.name << "\",";
	os << "\"argRequired\":" << std::boolalpha << f.arg_required << ",";
	os << "\"desc\":\"" << f.description << "\"";
	os << "}";

	return os;
}

std::ostream& operator<< (std::ostream &os, std::list<plugin_field> const &fields)
{
	bool first = true;
	os << "[";
	for(auto &f : fields)
	{
		os << (!first ? "," : "");
		os << f;
		first = false;
	}

	os << "]";
	return os;
}

// Info about a plugin. A plugin will fill this in in get_info().
typedef struct plugin_info {
	uint32_t id;
	std::string name;
	std::string description;
	std::string contact;
	std::string version;
	std::string event_source;
	std::list<plugin_field> fields;
} plugin_info;

// A friendlier view into a plugin_event, used in next().
//
// This is *not* used in extract_{xxx}, though, as the plugin API only
// uses opaque data pointers which can't be converted back to a
// plugin_event without performing a wasteful data copy or forcing use
// of a non-custom container on top of the data pointer.
typedef struct plugin_event {
	uint64_t evtnum;
	std::vector<uint8_t> data;
	uint64_t ts;
} plugin_event;

// The interface from the sdk to a plugin instance. Classes that
// derive from plugin_instance should overrirde all of these methods.
class plugin_instance_iface {
public:
	// Open a plugin instance. params is the open parameters as
	// defined by the plugin. Returns SS_PLUGIN_SUCCESS on
	// success, SS_PLUGIN_FAILURE on failure. The plugin should
	// call the plugin's set_last_error() method to set an
	// appropriate error string.
	virtual ss_plugin_rc open(const char* params) = 0;

	// Close a plugin instance. The instance object will be
	// destroyed shortly afterward.
	virtual void close() = 0;

	// Return a single event to the sdk. The sdk will handle
	// managing memory for the events and passing them up to the
	// plugin framework via plugin_next_batch.
	//
	// Returns one of the following:
	//  - SS_PLUGIN_SUCCESS: event ready and returned
	//  - SS_PLUGIN_FAILURE: some error, no event returned.
	//    framework will close instance.
	//  - SS_PLUGIN_TIMEOUT: no event ready. framework
	//    will try again later.
	//  - SS_PLUGIN_EOF: no more events. framework will
	//    close instance.
	virtual ss_plugin_rc next(plugin_event &evt) = 0;

	// This function is optional--the default implementation returns a progress_pct of 0.
	virtual const char* get_progress(uint32_t &progress_pct)
	{
		progress_pct = 0;
		return "0";
	}
};

class source_plugin;

// The sdk implementation of a plugin instance. Derived classes do not
// need to worry about the details of this implementation.
class plugin_instance : public plugin_instance_iface {
public:
        plugin_instance()
		: m_pevents(NULL)
	{
	};

	virtual ~plugin_instance() {};

	ss_plugin_rc plugin_next_batch(uint32_t *nevts, ss_plugin_event **evts)
	{
		m_events.clear();

		ss_plugin_rc res = SS_PLUGIN_SUCCESS;

		while (m_events.size() < s_max_batch_events)
		{
			std::shared_ptr<plugin_event> evt = std::make_shared<plugin_event>();

			res = next(*evt);

			if(res == SS_PLUGIN_SUCCESS)
			{
				m_events.push_back(evt);
			}
			else
			{
				break;
			}
		}

		// If the last result was Timeout/EOF, but there actually are
		// some events, return success instead. (This could happen if
		// nextf returned some events and then a Timeout/EOF).
		if((res == SS_PLUGIN_TIMEOUT || res == SS_PLUGIN_EOF) && m_events.size() > 0)
		{
			res = SS_PLUGIN_SUCCESS;
		}

		m_pevents = (ss_plugin_event *) realloc(m_pevents, m_events.size() * sizeof(ss_plugin_event));
		for(uint32_t i = 0; i < m_events.size(); i++)
		{
			m_pevents[i].data = m_events[i]->data.data();
			m_pevents[i].datalen = m_events[i]->data.size();
			m_pevents[i].ts = m_events[i]->ts;
		}

		*nevts = m_events.size();
		*evts = m_pevents;

		return res;
	}

private:

	static const uint32_t s_max_batch_events = 512;

	std::vector<std::shared_ptr<plugin_event>> m_events;
	ss_plugin_event *m_pevents;
};

// The interface from a sdk to a source plugin. Classes that derive
// from source_plugin should override all of these methods.
class source_plugin_iface {
public:
	// Return info about this source plugin.
	virtual void get_info(plugin_info &info) = 0;

	// Initialize this plugin. config is the init config as
	// defined by the plugin. Returns SS_PLUGIN_SUCCESS on
	// success, SS_PLUGIN_FAILURE on failure. There isn't any need
	// to set an error string via set_last_error() as the Plugin
	// API doesn't pass back error strings from plugin_init.
	virtual ss_plugin_rc init(const char* config) = 0;

	// Destroy this plugin. The plugin object will be destroyed
	// shortly afterward.
	virtual void destroy() = 0;

	// Create a plugin instance associated with this plugin and
	// return it. The source_plugin is provided in case the
	// dervived class wants to save the plugin reference in the
	// instance.
	virtual plugin_instance *create_instance(source_plugin &plugin) = 0;

	// Return a string representation of the provided event and return it.
	virtual std::string event_to_string(const uint8_t *data, uint32_t datalen) = 0;

	// Extract a single string field from the provided event and
	// fill in extract_val with the result. Return true if the
	// provided field is known to the plugin and the event has a
	// value for the provided field.
	virtual bool extract_str(const ss_plugin_event &evt, const std::string &field, const std::string &arg, std::string &extract_val) = 0;

	// Extract a single uint64_t field from the provided event and
	// fill in extract_val with the result. Return true if the
	// provided field is known to the plugin and the event has a
	// value for the provided field.
	virtual bool extract_u64(const ss_plugin_event &evt, const std::string &field, const std::string &arg, uint64_t &extract_val) = 0;
};

// The sdk implementation of a source plugin. Derived classes do not
// need to worry about the details of this implementation.
class source_plugin : public source_plugin_iface {
public:
	source_plugin()
	{
	};

	virtual ~source_plugin()
	{
		for(auto i : m_open_instances)
		{
			i->close();
			delete i;
		}
	};

	void set_last_error(const std::string &error)
	{
		m_last_error = error;
	}

	void update_info()
	{
		if(m_info.name == "")
		{
			get_info(m_info);
		}
	}

	uint32_t plugin_get_id()
	{
		update_info();
		return m_info.id;
	}

	const char* plugin_get_name()
	{
		update_info();
		return m_info.name.c_str();
	}

	const char* plugin_get_description()
	{
		update_info();
		return m_info.description.c_str();
	}

	const char* plugin_get_contact()
	{
		update_info();
		return m_info.contact.c_str();
	}

	const char* plugin_get_version()
	{
		update_info();
		return m_info.version.c_str();
	}

	const char* plugin_get_event_source()
	{
		update_info();
		return m_info.event_source.c_str();
	}

	const char* plugin_get_fields()
	{
		update_info();

		std::ostringstream os;
		os << m_info.fields;
		m_fields_json = os.str();

		return m_fields_json.c_str();
	}

	const char* plugin_get_last_error()
	{
		return m_last_error.c_str();
	}

	ss_instance_t *plugin_open(const char* params, ss_plugin_rc* rc)
	{
		plugin_instance *i = create_instance(*this);

		*rc = i->open(params);

		if(*rc == SS_PLUGIN_SUCCESS)
		{
			m_open_instances.insert(i);

			return i;
		}

		return NULL;
	}

	void plugin_close(ss_instance_t* i)
	{
		plugin_instance *pi = (plugin_instance *) i;

		pi->close();

		m_open_instances.erase(pi);
	}

	const char* plugin_event_to_string(const uint8_t *data, uint32_t datalen)
	{
		m_last_evtstr = event_to_string(data, datalen);

		return m_last_evtstr.c_str();
	}

	ss_plugin_rc plugin_extract_fields(const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)
	{
		m_extract_strs.clear();

		for(uint32_t i = 0; i < num_fields; i++)
		{
			std::string estr;
			std::string field_str = fields[i].field;
			std::string arg_str = fields[i].arg;

			switch(fields[i].ftype)
			{
			case FTYPE_UINT64:
				fields[i].field_present = extract_u64(*evt, field_str, arg_str, fields[i].res_u64);
				break;
			case FTYPE_STRING:
				fields[i].field_present = extract_str(*evt, field_str, arg_str, estr);
				if(fields[i].field_present)
				{
					m_extract_strs.push_back(estr);
					fields[i].res_str = m_extract_strs.back().c_str();
				}
			}
		}

		return SS_PLUGIN_SUCCESS;
	}

private:
	plugin_info m_info;
	std::string m_fields_json;
	std::string m_last_error;
	std::string m_last_evtstr;
	std::set<plugin_instance *> m_open_instances;
	std::list<std::string> m_extract_strs;
};

} // namespace falcosecurity


// This macro should be called exactly once per shared library. Pass
// the name of the derived class that implements a source plugin and
// the name of the derived class that implements a plugin
// instance. These functions are the ones called by the plugin
// framework.
#define GEN_SOURCE_PLUGIN_API_HOOKS(source_plugin_class_name, source_plugin_instance_name) \
static source_plugin_class_name g_plugin; \
 \
extern "C"				       \
const char* plugin_get_required_api_version()  \
{  \
	return "0.1.0";  \
}  \
  \
extern "C"  \
uint32_t plugin_get_type()  \
{  \
	return TYPE_SOURCE_PLUGIN;  \
}  \
  \
extern "C"  \
uint32_t plugin_get_id()  \
{  \
	return g_plugin.plugin_get_id();  \
}  \
  \
extern "C"  \
const char* plugin_get_name()  \
{  \
	return g_plugin.plugin_get_name();  \
}  \
  \
extern "C"  \
const char* plugin_get_description()  \
{  \
	return g_plugin.plugin_get_description();  \
}  \
  \
extern "C"  \
const char* plugin_get_contact()  \
{  \
	return g_plugin.plugin_get_contact();  \
}  \
  \
extern "C"  \
const char* plugin_get_version()  \
{  \
	return g_plugin.plugin_get_version();  \
}  \
  \
extern "C"  \
const char* plugin_get_event_source()  \
{  \
	return g_plugin.plugin_get_event_source();  \
}  \
  \
extern "C"  \
const char* plugin_get_fields()  \
{  \
	return g_plugin.plugin_get_fields();  \
}  \
  \
extern "C"  \
const char* plugin_get_last_error(ss_plugin_t* s)  \
{  \
	source_plugin_class_name *plugin = (source_plugin_class_name *) s;  \
	return plugin->plugin_get_last_error();  \
}  \
  \
extern "C"  \
ss_plugin_t* plugin_init(const char* config, ss_plugin_rc* rc)  \
{  \
	source_plugin_class_name *plugin = new source_plugin_class_name();  \
  \
	*rc = plugin->init(config);  \
  \
	if(*rc != SS_PLUGIN_SUCCESS)  \
	{  \
		delete plugin;  \
	}  \
  \
	return plugin;  \
}  \
  \
extern "C"  \
void plugin_destroy(ss_plugin_t* s)  \
{  \
	source_plugin_class_name *plugin = (source_plugin_class_name *) s;  \
	delete plugin;  \
}  \
  \
extern "C"  \
ss_instance_t* plugin_open(ss_plugin_t* s, const char* params, ss_plugin_rc* rc)  \
{  \
	source_plugin_class_name *plugin = (source_plugin_class_name *) s;  \
  \
	return plugin->plugin_open(params, rc);  \
}  \
  \
extern "C"  \
void plugin_close(ss_plugin_t* s, ss_instance_t* i)  \
{  \
	source_plugin_class_name *plugin = (source_plugin_class_name *) s;  \
  \
	return plugin->plugin_close(i);  \
}  \
  \
extern "C"  \
ss_plugin_rc plugin_next_batch(ss_plugin_t* s, ss_instance_t* i, uint32_t *nevts, ss_plugin_event **evts)  \
{  \
	source_plugin_instance_name *instance = (source_plugin_instance_name *) i;  \
  \
	return instance->plugin_next_batch(nevts, evts);  \
}  \
extern "C"  \
const char* plugin_get_progress(ss_plugin_t* s, ss_instance_t* i, uint32_t* progress_pct)  \
{  \
	source_plugin_instance_name *instance = (source_plugin_instance_name *) i;  \
  \
        return instance->get_progress(*progress_pct);  \
}  \
  \
extern "C"  \
const char* plugin_event_to_string(ss_plugin_t *s, const uint8_t *data, uint32_t datalen)  \
{  \
	source_plugin_class_name *plugin = (source_plugin_class_name *) s;  \
	return plugin->plugin_event_to_string(data, datalen);  \
}  \
  \
extern "C"  \
ss_plugin_rc plugin_extract_fields(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields)  \
{  \
	source_plugin_class_name *plugin = (source_plugin_class_name *) s;  \
	return plugin->plugin_extract_fields(evt, num_fields, fields);  \
}
