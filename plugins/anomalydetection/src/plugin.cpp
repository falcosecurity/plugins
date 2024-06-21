// SPDX-License-Identifier: Apache-2.0
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

#include "plugin.h"

void anomalydetection::log_error(std::string err_mess)
{
    printf("%s %s\n", PLUGIN_LOG_PREFIX, err_mess.c_str());
}

//////////////////////////
// Initializations
//////////////////////////

falcosecurity::init_schema anomalydetection::get_init_schema()
{
    falcosecurity::init_schema init_schema;
    init_schema.schema_type =
            falcosecurity::init_schema_type::SS_PLUGIN_SCHEMA_JSON;
    init_schema.schema = R"(
{
  "$schema": "http://json-schema.org/draft-04/schema#",
  "type": "object",
  "properties": {
    "count_min_sketch": {
      "type": "object",
      "properties": {
        "enabled": {
          "type": "boolean"
        },
        "n_sketches": {
          "type": "integer",
          "minimum": 1
        },
        "gamma_eps": {
          "type": "array",
          "items": {
            "type": "array",
            "items": [
              {
                "type": "number"
              },
              {
                "type": "number"
              }
            ],
            "minItems": 0,
            "maxItems": 2
          },
          "minItems": 1
        },
        "rows_cols": {
          "type": "array",
          "items": {
            "type": "array",
            "items": [
              {
                "type": "number"
              },
              {
                "type": "number"
              }
            ],
            "minItems": 2,
            "maxItems": 2
          },
          "minItems": 1
        },
        "behavior_profiles": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "fields": {
                "type": "string",
                "description": "The anomalydetection behavior profile string including the fields."
              },
              "event_codes": {
                "type": "array",
                "description": "The list of PPME event codes to which the behavior profile updates should be applied.",
                "items": {
                  "type": "number",
                  "description": "PPME event codes supported by Falco."
                }
              }
            },
            "required": [
              "fields",
              "event_codes"
            ]
          },
          "minItems": 1
        }
      }
    }
  }
})";
    return init_schema;
}

void anomalydetection::parse_init_config(nlohmann::json& config_json)
{
    if(config_json.contains(nlohmann::json::json_pointer("/count_min_sketch")))
    {
        if(config_json.contains(nlohmann::json::json_pointer("/count_min_sketch/enabled")))
        {
            config_json.at(nlohmann::json::json_pointer("/count_min_sketch/enabled"))
                    .get_to(m_count_min_sketch_enabled);
        }

        // Config JSON schema enforces a minimum of 1 sketches
        if(config_json.contains(nlohmann::json::json_pointer("/count_min_sketch/n_sketches")))
        {
            config_json.at(nlohmann::json::json_pointer("/count_min_sketch/n_sketches"))
                    .get_to(m_n_sketches);
        }

        // If used, config JSON schema enforces a minimum of 1 items and 2-d sub-arrays
        auto gamma_eps_pointer = nlohmann::json::json_pointer("/count_min_sketch/gamma_eps");
        if (config_json.contains(gamma_eps_pointer) && config_json[gamma_eps_pointer].is_array())
        {
            for (const auto& array : config_json[gamma_eps_pointer])
            {
                if (array.is_array() && array.size() == 2)
                {
                    std::vector<double> sub_array = {array[0].get<double>(), array[1].get<double>()};
                    m_gamma_eps.emplace_back(sub_array);
                }
            }
        }

        // If used, config JSON schema enforces a minimum of 1 items and 2-d sub-arrays
        auto rows_cols_pointer = nlohmann::json::json_pointer("/count_min_sketch/rows_cols");
        if (config_json.contains(rows_cols_pointer) && config_json[rows_cols_pointer].is_array())
        {
            for (const auto& array : config_json[rows_cols_pointer])
            {
                if (array.is_array() && array.size() == 2)
                {
                    std::vector<uint64_t> sub_array = {array[0].get<uint64_t>(), array[1].get<uint64_t>()};
                    m_rows_cols.emplace_back(sub_array);
                }
            }
        }

        // Config JSON schema enforces a minimum of 1 item
        auto behavior_profiles_pointer = nlohmann::json::json_pointer("/count_min_sketch/behavior_profiles");
        if (config_json.contains(behavior_profiles_pointer) && config_json[behavior_profiles_pointer].is_array())
        {
            const auto& behavior_profiles = config_json[behavior_profiles_pointer];
            for (const auto& profile : behavior_profiles)
            {
                std::vector<plugin_sinsp_filterchecks_field> filter_check_fields;
                std::unordered_set<ppm_event_code> codes;
                if (profile.contains("fields") && profile.contains("event_codes"))
                {
                    filter_check_fields = plugin_anomalydetection::utils::get_profile_fields(profile["fields"].get<std::string>());
                    for (const auto& code : profile["event_codes"])
                    {
                        codes.insert((ppm_event_code)code.get<uint64_t>());
                    }
                }
                m_behavior_profiles_fields.emplace_back(filter_check_fields);
                m_behavior_profiles_event_codes.emplace_back(std::move(codes));
            }
        }

        // Check correlated conditions that can't be directly enforced by the config JSON schema
        if (!m_gamma_eps.empty() && m_n_sketches != m_gamma_eps.size())
        {
            log_error("Config gamma_eps needs to match the specified number of sketches");
            assert(false);
        }
        if (!m_rows_cols.empty() && m_n_sketches != m_rows_cols.size())
        {
            log_error("Config rows_cols needs to match the specified number of sketches");
            assert(false);
        }
        if (m_n_sketches != m_behavior_profiles_fields.size())
        {
            log_error("Config behavior_profiles needs to match the specified number of sketches");
            assert(false);
        }
        if (m_n_sketches != m_behavior_profiles_event_codes.size())
        {
            log_error("Config behavior_profiles needs to match the specified number of sketches");
            assert(false);
        }
    }
}

bool anomalydetection::init(falcosecurity::init_input& in)
{
    using st = falcosecurity::state_value_type;
    auto& t = in.tables();

    // This should never happen, the config is validated by the framework
    if(in.get_config().empty())
    {
        return false;
    }

    auto cfg = nlohmann::json::parse(in.get_config());
    parse_init_config(cfg);

    //////////////////////////
    // Init fields
    //////////////////////////

    try
    {
        // Accessor to falcosecurity/libs' thread table (process cache / core state engine)
        m_thread_table = t.get_table(THREAD_TABLE_NAME, st::SS_PLUGIN_ST_INT64);
        // Define accessors to falcosecurity/libs' thread table fields
        m_tid = m_thread_table.get_field(t.fields(), "tid", st::SS_PLUGIN_ST_INT64);
        m_pid = m_thread_table.get_field(t.fields(), "pid", st::SS_PLUGIN_ST_INT64);
        m_ptid = m_thread_table.get_field(t.fields(), "ptid", st::SS_PLUGIN_ST_INT64);
        m_sid = m_thread_table.get_field(t.fields(), "sid", st::SS_PLUGIN_ST_INT64);
        m_comm = m_thread_table.get_field(t.fields(), "comm", st::SS_PLUGIN_ST_STRING);
        m_exe = m_thread_table.get_field(t.fields(), "exe", st::SS_PLUGIN_ST_STRING);
        m_exepath = m_thread_table.get_field(t.fields(), "exe_path", st::SS_PLUGIN_ST_STRING);
        m_exe_writable = m_thread_table.get_field(t.fields(), "exe_writable", st::SS_PLUGIN_ST_BOOL);
        m_exe_upper_layer = m_thread_table.get_field(t.fields(), "exe_upper_layer", st::SS_PLUGIN_ST_BOOL);
        m_exe_from_memfd = m_thread_table.get_field(t.fields(), "exe_from_memfd", st::SS_PLUGIN_ST_BOOL);
        // m_args = m_thread_table.get_field(t.fields(), "args", TBD);
        // m_env = m_thread_table.get_field(t.fields(), "env", TBD);
        m_container_id = m_thread_table.get_field(t.fields(), "container_id", st::SS_PLUGIN_ST_STRING);
        // m_user = m_thread_table.get_field(t.fields(), "user", TBD);
        // m_loginuser = m_thread_table.get_field(t.fields(), "loginuser", TBD);
        // m_group = m_thread_table.get_field(t.fields(), "group", TBD);
        m_vtid = m_thread_table.get_field(t.fields(), "vtid", st::SS_PLUGIN_ST_INT64);
        m_vpid = m_thread_table.get_field(t.fields(), "vpid", st::SS_PLUGIN_ST_INT64);
        m_vpgid = m_thread_table.get_field(t.fields(), "vpgid", st::SS_PLUGIN_ST_INT64);
        m_tty = m_thread_table.get_field(t.fields(), "tty", st::SS_PLUGIN_ST_UINT32);
        m_cwd = m_thread_table.get_field(t.fields(), "cwd", st::SS_PLUGIN_ST_STRING);
    }
    catch(falcosecurity::plugin_exception e)
    {
        m_lasterr = "cannot init libs' thread table info fields: '" + std::string(e.what());
        return false;
    }

    //////////////////////////
    // Init sketches
    //////////////////////////

    // Init the plugin managed state table holding the count min sketch estimates for each behavior profile
    if (m_rows_cols.size() == m_n_sketches)
    {
        for (uint32_t i = 0; i < m_n_sketches; ++i)
        {
            uint64_t rows = m_rows_cols[i][0];
            uint64_t cols = m_rows_cols[i][1];
            m_count_min_sketches.push_back(std::make_unique<plugin::anomalydetection::num::cms<uint64_t>>(rows, cols));
        }
    } else if (m_gamma_eps.size() == m_n_sketches && m_rows_cols.empty())
    {
        for (uint32_t i = 0; i < m_n_sketches; ++i)
        {
            double gamma = m_gamma_eps[i][0];
            double eps = m_gamma_eps[i][1];
            m_count_min_sketches.push_back(std::make_unique<plugin::anomalydetection::num::cms<uint64_t>>(gamma, eps));
        }
    } else
    {
        return false;
    }

    return true;
}

//////////////////////////
// Extract capability
//////////////////////////

std::vector<falcosecurity::field_info> anomalydetection::get_fields()
{
    using ft = falcosecurity::field_value_type;
    const falcosecurity::field_info fields[] = {
            {ft::FTYPE_UINT64, "anomaly.count_min_sketch", 
             "Count Min Sketch Estimate",
             "Count Min Sketch Estimate according to the specified behavior profile for a predefined set of {syscalls} events. Access different behavior profiles/sketches using indices. For instance, anomaly.count_min_sketch[0] retrieves the first behavior profile defined in the plugins' `init_config`.",
             { // field arg
                false, // key
                true,  // index
                false,
             }},
            {ft::FTYPE_STRING, "anomaly.count_min_sketch.profile", 
             "Behavior Profile Concatenated String",
             "Concatenated string according to the specified behavior profile (not preserving original order). Access different behavior profiles using indices. For instance, anomaly.count_min_sketch.profile[0] retrieves the first behavior profile defined in the plugins' `init_config`.",
             { // field arg
                false, // key
                true,  // index
                false,
             }},
    };
    const int fields_size = sizeof(fields) / sizeof(fields[0]);
    static_assert(fields_size == ANOMALYDETECTION_FIELD_MAX, "Wrong number of anomaly fields.");
    return std::vector<falcosecurity::field_info>(fields, fields + fields_size);
}

bool anomalydetection::extract(const falcosecurity::extract_fields_input& in)
{
    auto& req = in.get_extract_request();
    auto& tr = in.get_table_reader();
    int64_t thread_id = in.get_event_reader().get_tid();
    uint64_t count_min_sketch_estimate = 0;
    std::string behavior_profile_concat_str;
    auto index = req.get_arg_index();
    if(index >= m_n_sketches)
    {
        m_lasterr = "sketch index out of bounds";
        return false;
    }
    switch(req.get_field_id())
    {
    case ANOMALYDETECTION_COUNT_MIN_SKETCH_COUNT:
        if(extract_filterchecks_concat_profile(thread_id, tr, m_behavior_profiles_fields[index], behavior_profile_concat_str))
        {
            count_min_sketch_estimate = m_count_min_sketches[index].get()->estimate(behavior_profile_concat_str);
            req.set_value(count_min_sketch_estimate, true);
        }
        return true;
    case ANOMALYDETECTION_COUNT_MIN_SKETCH_BEHAVIOR_PROFILE_CONCAT_STR:
        if(extract_filterchecks_concat_profile(thread_id, tr, m_behavior_profiles_fields[index], behavior_profile_concat_str))
        {
            req.set_value(behavior_profile_concat_str, true);
        }
        return true;
    default:
        m_lasterr = "unknown extraction request";
        return false;
    }

    return true;
}

//////////////////////////
// Parse capability
//////////////////////////

bool anomalydetection::extract_filterchecks_concat_profile(int64_t thread_id, const falcosecurity::table_reader &tr, const std::vector<plugin_sinsp_filterchecks_field>& fields, std::string& behavior_profile_concat_str)
{
    falcosecurity::table_entry thread_entry = m_thread_table.get_entry(tr, thread_id);

    if(thread_entry == nullptr)
    {
        return false;
    }

    // Create a concatenated string formed out of each field per behavior profile
    // No concept of null fields (instead its always an empty string) compared to libsinsp
    for (const auto& field : fields)
    {
        std::string tstr;
        uint32_t tuint32 = UINT32_MAX;
        int64_t tint64 = -1;
        int64_t ptid = -1;
        falcosecurity::table_entry lineage;
        falcosecurity::table_entry leader;
        switch(field.id)
        {
        case plugin_sinsp_filterchecks::TYPE_CONTAINER_ID:
            m_container_id.read_value(tr, thread_entry, tstr);
            break;
        case plugin_sinsp_filterchecks::TYPE_NAME:
            m_comm.read_value(tr, thread_entry, tstr);
            break;
        case plugin_sinsp_filterchecks::TYPE_PNAME:
            m_ptid.read_value(tr, thread_entry, ptid);
            lineage = m_thread_table.get_entry(tr, ptid);
            m_comm.read_value(tr, lineage, tstr);
            break;
        case plugin_sinsp_filterchecks::TYPE_ANAME:
            {
                // todo: check implications of main thread as it's part of the libs implementation
                if(field.argid < 1)
                {
                    m_comm.read_value(tr, thread_entry, tstr);
                    break;
                }
                m_ptid.read_value(tr, thread_entry, ptid);
                for(uint32_t j = 0; j < field.argid; j++)
                {
                    try
                    {
                        lineage = m_thread_table.get_entry(tr, ptid);
                        if(j == (field.argid - 1))
                        {
                            m_comm.read_value(tr, lineage, tstr);
                            break;
                        }
                        if(ptid == 1)
                        {
                            break;
                        }
                        m_ptid.read_value(tr, lineage, ptid);
                    }
                    catch(const std::exception& e)
                    {
                    }
                }
                break;
            }
        case plugin_sinsp_filterchecks::TYPE_EXE:
            m_exe.read_value(tr, thread_entry, tstr);
            break;
        case plugin_sinsp_filterchecks::TYPE_PEXE:
            m_ptid.read_value(tr, thread_entry, ptid);
            lineage = m_thread_table.get_entry(tr, ptid);
            m_exe.read_value(tr, lineage, tstr);
            break;
        case plugin_sinsp_filterchecks::TYPE_AEXE:
            {
                if(field.argid < 1)
                {
                    m_exe.read_value(tr, thread_entry, tstr);
                    break;
                }
                m_ptid.read_value(tr, thread_entry, ptid);
                for(uint32_t j = 0; j < field.argid; j++)
                {
                    try
                    {
                        lineage = m_thread_table.get_entry(tr, ptid);
                        if(j == (field.argid - 1))
                        {
                            m_exe.read_value(tr, lineage, tstr);
                            break;
                        }
                        if(ptid == 1)
                        {
                            break;
                        }
                        m_ptid.read_value(tr, lineage, ptid);
                    }
                    catch(const std::exception& e)
                    {
                    }
                }
                break;
            }
        case plugin_sinsp_filterchecks::TYPE_EXEPATH:
            m_exepath.read_value(tr, thread_entry, tstr);
            break;
        case plugin_sinsp_filterchecks::TYPE_PEXEPATH:
            m_ptid.read_value(tr, thread_entry, ptid);
            lineage = m_thread_table.get_entry(tr, ptid);
            m_exepath.read_value(tr, lineage, tstr);
            break;
        case plugin_sinsp_filterchecks::TYPE_AEXEPATH:
            {
                if(field.argid < 1)
                {
                    m_exepath.read_value(tr, thread_entry, tstr);
                    break;
                }
                m_ptid.read_value(tr, thread_entry, ptid);
                for(uint32_t j = 0; j < field.argid; j++)
                {
                    try
                    {
                        lineage = m_thread_table.get_entry(tr, ptid);
                        if(j == (field.argid - 1))
                        {
                            m_exepath.read_value(tr, lineage, tstr);
                            break;
                        }
                        if(ptid == 1)
                        {
                            break;
                        }
                        m_ptid.read_value(tr, lineage, ptid);
                    }
                    catch(const std::exception& e)
                    {
                    }
                }
                break;
            }
        case plugin_sinsp_filterchecks::TYPE_CWD:
            m_cwd.read_value(tr, thread_entry, tstr);
            break;
        case plugin_sinsp_filterchecks::TYPE_TTY:
            m_tty.read_value(tr, thread_entry, tuint32);
            tstr = std::to_string(tuint32);
            break;
        case plugin_sinsp_filterchecks::TYPE_PID:
            m_pid.read_value(tr, thread_entry, tint64);
            tstr = std::to_string(tint64);
            break;
        case plugin_sinsp_filterchecks::TYPE_PPID:
            m_ptid.read_value(tr, thread_entry, ptid);
            lineage = m_thread_table.get_entry(tr, ptid);
            m_pid.read_value(tr, lineage, tint64);
            tstr = std::to_string(tint64);
            break;
        case plugin_sinsp_filterchecks::TYPE_APID:
            {
                if(field.argid < 1)
                {
                    m_pid.read_value(tr, thread_entry, tint64);
                    break;
                }
                m_ptid.read_value(tr, thread_entry, ptid);
                for(uint32_t j = 0; j < field.argid; j++)
                {
                    try
                    {
                        lineage = m_thread_table.get_entry(tr, ptid);
                        if(j == (field.argid - 1))
                        {
                            m_pid.read_value(tr, lineage, tint64);
                            break;
                        }
                        if(ptid == 1)
                        {
                            break;
                        }
                        m_ptid.read_value(tr, lineage, ptid);
                    }
                    catch(const std::exception& e)
                    {
                    }
                }
                break;
            }
        case plugin_sinsp_filterchecks::TYPE_VPID:
            m_vpid.read_value(tr, thread_entry, tint64);
            tstr = std::to_string(tint64);
            break;
        case plugin_sinsp_filterchecks::TYPE_PVPID:
            m_ptid.read_value(tr, thread_entry, ptid);
            lineage = m_thread_table.get_entry(tr, ptid);
            m_vpid.read_value(tr, lineage, tint64);
            tstr = std::to_string(tint64);
            break;
        case plugin_sinsp_filterchecks::TYPE_SID:
            m_sid.read_value(tr, thread_entry, tint64);
            tstr = std::to_string(tint64);
            break;
        // todo better unit tests and double check the parent lineage traversal fields in general
        case plugin_sinsp_filterchecks::TYPE_SNAME:
            {
                int64_t sid;
                m_sid.read_value(tr, thread_entry, sid);
                m_ptid.read_value(tr, thread_entry, ptid);
                leader = thread_entry;
                for(uint32_t j = 0; j < 9; j++)
                {
                    try
                    {
                        lineage = m_thread_table.get_entry(tr, ptid);
                        m_sid.read_value(tr, lineage, tint64);
                        if(sid != tint64)
                        {
                            break;
                        }
                        m_ptid.read_value(tr, lineage, ptid);
                        leader = lineage;
                    }
                    catch(const std::exception& e)
                    {
                    }
                }
                m_comm.read_value(tr, leader, tstr);
                break;
            }
        case plugin_sinsp_filterchecks::TYPE_VPGID:
            m_vpgid.read_value(tr, thread_entry, tint64);
            tstr = std::to_string(tint64);
            break;
        case plugin_sinsp_filterchecks::TYPE_VPGID_NAME:
            {
                int64_t vpgid;
                m_vpgid.read_value(tr, thread_entry, vpgid);
                m_ptid.read_value(tr, thread_entry, ptid);
                leader = thread_entry;
                for(uint32_t j = 0; j < 5; j++)
                {
                    try
                    {
                        lineage = m_thread_table.get_entry(tr, ptid);
                        m_vpgid.read_value(tr, lineage, tint64);
                        if(vpgid != tint64)
                        {
                            break;
                        }
                        m_ptid.read_value(tr, lineage, ptid);
                        leader = lineage;
                    }
                    catch(const std::exception& e)
                    {
                    }
                }
                m_comm.read_value(tr, leader, tstr);
                break;
            }
        default:
            break;
        }
        behavior_profile_concat_str += tstr;
    }
    return true;
}

bool anomalydetection::parse_event(const falcosecurity::parse_event_input& in)
{
    auto& evt = in.get_event_reader();
    auto& tr = in.get_table_reader();

    // note: Plugin event parsing guaranteed to happen after libs' `sinsp_parser::process_event` has finished.
    // Needs to stay in sync w/ libs updates.
    // Ultimately gated by `base_syscalls` restrictions if Falco is used w/ `base_syscalls`.
    int i = 0;
    std::string behavior_profile_concat_str;
    for(const auto& set : m_behavior_profiles_event_codes)
    {
        if(set.find((ppm_event_code)evt.get_type()) != set.end())
        {
            int64_t thread_id = in.get_event_reader().get_tid();
            if(thread_id <= 0)
            {
                return false;
            }
            try
            {
                behavior_profile_concat_str.clear();
                if (i < m_n_sketches && extract_filterchecks_concat_profile(thread_id, tr, m_behavior_profiles_fields[i], behavior_profile_concat_str) && !behavior_profile_concat_str.empty())
                {
                    m_count_min_sketches[i].get()->update(behavior_profile_concat_str, (uint64_t)1);
                }
            }
            catch(falcosecurity::plugin_exception e)
            {
                return false;
            }
        }
        i++;
    }
    return true;
}
