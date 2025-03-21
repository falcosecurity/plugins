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

#include "plugin.h"
#include "plugin_config_schema.h"
#ifdef _HAS_ASYNC
#include "caps/async/async.tpp"
#endif

//////////////////////////
// General plugin API
//////////////////////////

std::string my_plugin::get_name() { return PLUGIN_NAME; }

std::string my_plugin::get_version() { return PLUGIN_VERSION; }

std::string my_plugin::get_description() { return PLUGIN_DESCRIPTION; }

std::string my_plugin::get_contact() { return PLUGIN_CONTACT; }

std::string my_plugin::get_required_api_version()
{
    return PLUGIN_REQUIRED_API_VERSION;
}

std::string my_plugin::get_last_error() { return m_lasterr; }

void my_plugin::destroy()
{
    m_logger.log("detach the plugin",
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
}

falcosecurity::init_schema my_plugin::get_init_schema()
{
    falcosecurity::init_schema init_schema;
    init_schema.schema_type =
            falcosecurity::init_schema_type::SS_PLUGIN_SCHEMA_JSON;
    init_schema.schema = plugin_schema_string;
    return init_schema;
}

void my_plugin::parse_init_config(nlohmann::json& config_json)
{
    m_cfg = config_json.get<PluginConfig>();
    m_cfg.log_engines(m_logger);
}

bool my_plugin::init(falcosecurity::init_input& in)
{
    using st = falcosecurity::state_value_type;
    auto& t = in.tables();

    m_logger = in.get_logger();

    // This should never happen, the config is validated by the framework
    if(in.get_config().empty())
    {
        m_lasterr = "cannot find the init config for the plugin";
        m_logger.log(m_lasterr,
                     falcosecurity::_internal::SS_PLUGIN_LOG_SEV_CRITICAL);
        return false;
    }

    auto cfg = nlohmann::json::parse(in.get_config());
    parse_init_config(cfg);

    m_logger.log("init the plugin",
                 falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);

    m_mgr = std::make_unique<matcher_manager>(m_cfg.engines);

    try
    {
        // Expose containers as libsinsp state table
        t.add_table(get_table());

        m_threads_table =
                t.get_table(THREAD_TABLE_NAME, st::SS_PLUGIN_ST_INT64);

        // pidns_init_start_ts used by TYPE_CONTAINER_START_TS and
        // TYPE_CONTAINER_DURATION extractors
        m_threads_field_pidns_init_start_ts = m_threads_table.get_field(
                t.fields(), PIDNS_INIT_START_TS_FIELD_NAME,
                st::SS_PLUGIN_ST_UINT64);

        // vpid and ptid are used to attach the category field to the thread
        // entry
        m_threads_field_vpid = m_threads_table.get_field(
                t.fields(), VPID_FIELD_NAME, st::SS_PLUGIN_ST_INT64);
        m_threads_field_ptid = m_threads_table.get_field(
                t.fields(), PTID_FIELD_NAME, st::SS_PLUGIN_ST_INT64);

        // get the 'args' field accessor from the thread table
        m_threads_field_args = m_threads_table.get_field(
                t.fields(), "args", st::SS_PLUGIN_ST_TABLE);

        // get the 'value' field accessor from the args table
        m_args_field =
                t.get_subtable_field(m_threads_table, m_threads_field_args,
                                     "value", st::SS_PLUGIN_ST_STRING);

        // get the 'exe' field accessor from the thread table
        m_threads_field_exe = m_threads_table.get_field(
                t.fields(), "exe", st::SS_PLUGIN_ST_STRING);

        // get the 'cgroups' field accessor from the thread table
        m_threads_field_cgroups = m_threads_table.get_field(
                t.fields(), CGROUPS_TABLE_NAME, st::SS_PLUGIN_ST_TABLE);
        // get the 'second' field accessor from the cgroups table
        m_cgroups_field_second =
                t.get_subtable_field(m_threads_table, m_threads_field_cgroups,
                                     "second", st::SS_PLUGIN_ST_STRING);

        // Add the container_id field into thread table
        m_container_id_field = m_threads_table.add_field(
                t.fields(), CONTAINER_ID_FIELD_NAME, st::SS_PLUGIN_ST_STRING);

        // Add the category field into thread table
        m_threads_field_category = m_threads_table.add_field(
                t.fields(), CATEGORY_FIELD_NAME, st::SS_PLUGIN_ST_UINT16);
    }
    catch(falcosecurity::plugin_exception e)
    {
        m_lasterr = "cannot add the '" + std::string(CONTAINER_ID_FIELD_NAME) +
                    "' field into the '" + std::string(THREAD_TABLE_NAME) +
                    "' table: " + e.what();
        m_logger.log(m_lasterr,
                     falcosecurity::_internal::SS_PLUGIN_LOG_SEV_CRITICAL);
        return false;
    }

    // Initialize dummy host container entry
    m_containers[""] = container_info::host_container_info();

    // Initialize metrics
    falcosecurity::metric n_container(METRIC_N_CONTAINERS);
    n_container.set_value(0);
    m_metrics.push_back(n_container);

    falcosecurity::metric n_missing(METRIC_N_MISSING);
    n_missing.set_value(0);
    m_metrics.push_back(n_missing);

    return true;
}

const std::vector<falcosecurity::metric>& my_plugin::get_metrics()
{
    return m_metrics;
}

FALCOSECURITY_PLUGIN(my_plugin);

/* Utils */

std::string my_plugin::compute_container_id_for_thread(
        const falcosecurity::table_entry& thread_entry,
        const falcosecurity::table_reader& tr,
        std::shared_ptr<container_info>& info)
{
    // retrieve tid cgroups, compute container_id and store it.
    std::string container_id;
    using st = falcosecurity::state_value_type;

    // get the cgroups table of the thread
    auto cgroups_table = m_threads_table.get_subtable(
            tr, m_threads_field_cgroups, thread_entry, st::SS_PLUGIN_ST_UINT64);

    cgroups_table.iterate_entries(
            tr,
            [&](const falcosecurity::table_entry& e)
            {
                // read the "second" field (aka: the cgroup path)
                // from the current entry of the cgroups table
                std::string cgroup;
                m_cgroups_field_second.read_value(tr, e, cgroup);
                if(!cgroup.empty())
                {
                    m_mgr->match_cgroup(cgroup, container_id, info);
                    if(!container_id.empty())
                    {
                        m_logger.log(fmt::format("Matched container_id: {} "
                                                 "from cgroup {}",
                                                 container_id, cgroup),
                                     falcosecurity::_internal::
                                             SS_PLUGIN_LOG_SEV_TRACE);
                        // break the loop
                        return false;
                    }
                }
                return true;
            });
    return container_id;
}

// Same logic as
// https://github.com/falcosecurity/libs/blob/a99a36573f59c0e25965b36f8fa4ae1b10c5d45c/userspace/libsinsp/container.cpp#L438
void my_plugin::write_thread_category(
        const std::shared_ptr<const container_info>& cinfo,
        const falcosecurity::table_entry& thread_entry,
        const falcosecurity::table_reader& tr,
        const falcosecurity::table_writer& tw)
{
    using st = falcosecurity::state_value_type;

    int64_t vpid;
    m_threads_field_vpid.read_value(tr, thread_entry, vpid);
    if(vpid == 1)
    {
        uint16_t category = CAT_CONTAINER;
        m_threads_field_category.write_value(tw, thread_entry, category);
        return;
    }

    int64_t ptid;
    m_threads_field_ptid.read_value(tr, thread_entry, ptid);
    try
    {
        auto parent_entry = m_threads_table.get_entry(tr, ptid);
        uint16_t parent_category;
        m_threads_field_category.read_value(tr, parent_entry, parent_category);
        if(parent_category != CAT_NONE)
        {
            m_threads_field_category.write_value(tw, thread_entry,
                                                 parent_category);
            return;
        }
    }
    catch(falcosecurity::plugin_exception& ex)
    {
        // nothing
        m_logger.log("no parent thread found",
                     falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
    }

    // Read "exe" field
    std::string exe;
    m_threads_field_exe.read_value(tr, thread_entry, exe);
    // Read "args" field: collect args
    std::vector<std::string> args;
    auto args_table = m_threads_table.get_subtable(
            tr, m_threads_field_args, thread_entry, st::SS_PLUGIN_ST_INT64);
    args_table.iterate_entries(
            tr,
            [this, tr, &args](const falcosecurity::table_entry& e)
            {
                // read the arg field from the current entry of args
                // table
                std::string arg;
                m_args_field.read_value(tr, e, arg);
                if(!arg.empty())
                {
                    args.push_back(arg);
                }
                return true;
            });

    const auto ptype = cinfo->match_health_probe(exe, args);
    if(ptype == container_health_probe::PT_NONE)
    {
        return;
    }

    bool found_container_init = false;
    while(!found_container_init)
    {
        try
        {
            // Move to parent
            auto entry = m_threads_table.get_entry(tr, ptid);

            // Read vpid and container_id for parent
            int64_t vpid;
            std::string container_id;
            m_threads_field_vpid.read_value(tr, entry, vpid);
            m_container_id_field.read_value(tr, entry, container_id);

            if(vpid == 1 && !container_id.empty())
            {
                found_container_init = true;
            }
            else
            {
                // update ptid for next iteration
                m_threads_field_ptid.read_value(tr, entry, ptid);
            }
        }
        catch(falcosecurity::plugin_exception& ex)
        {
            // end of loop
            break;
        }
    }
    if(!found_container_init)
    {
        uint16_t category;
        // Each health probe type maps to a command category
        switch(ptype)
        {
        case container_health_probe::PT_NONE:
            break;
        case container_health_probe::PT_HEALTHCHECK:
            category = CAT_HEALTHCHECK;
            m_threads_field_category.write_value(tw, thread_entry, category);
            break;
        case container_health_probe::PT_LIVENESS_PROBE:
            category = CAT_LIVENESS_PROBE;
            m_threads_field_category.write_value(tw, thread_entry, category);
            break;
        case container_health_probe::PT_READINESS_PROBE:
            category = CAT_READINESS_PROBE;
            m_threads_field_category.write_value(tw, thread_entry, category);
            break;
        }
        return;
    }
}

void my_plugin::on_new_process(const falcosecurity::table_entry& thread_entry,
                               const falcosecurity::table_reader& tr,
                               const falcosecurity::table_writer& tw)
{
    std::shared_ptr<container_info> info = nullptr;
    auto container_id = compute_container_id_for_thread(thread_entry, tr, info);
    m_container_id_field.write_value(tw, thread_entry, container_id);

    if(info != nullptr)
    {
#ifdef _HAS_ASYNC
        // Since the matcher also returned a container_info,
        // it means we do not expect to receive any metadata from the go-worker,
        // since the engine has no listener SDK.
        // Just send the event now.
        nlohmann::json j(info);
        generate_async_event<ASYNC_HANDLER_DEFAULT>(j.dump().c_str(), true);
#endif
        // Immediately cache the container metadata
        m_containers[info->m_id] = info;
    }

    // Write thread category field
    if(!container_id.empty())
    {
        auto it = m_containers.find(container_id);
        if(it != m_containers.end())
        {
            auto cinfo = it->second;
            write_thread_category(cinfo, thread_entry, tr, tw);
        }
        else
        {
            m_logger.log(fmt::format("failed to write thread category, no "
                                     "container found "
                                     "for {}",
                                     container_id),
                         falcosecurity::_internal::SS_PLUGIN_LOG_SEV_DEBUG);
#ifdef _HAS_ASYNC
            // Check if already asked
            if(m_asked_containers.find(container_id) ==
               m_asked_containers.end())
            {
                m_asked_containers.insert(container_id);
                // Implemented by GO worker.go
                AskForContainerInfo(container_id.c_str());
            }
#endif
        }
    }
}