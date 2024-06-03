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

bool anomalydetection::init(falcosecurity::init_input& in)
{
    using st = falcosecurity::state_value_type;
    auto& t = in.tables();

    // This should never happen, the config is validated by the framework
    if(in.get_config().empty())
    {
        return false;
    }

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
        m_exe_from_memfd = m_thread_table.get_field(t.fields(), "exe_from_memfd", st::SS_PLUGIN_ST_BOOL); // missing in libs define_static_field
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

    // Init the plugin managed state table holding the count min sketch estimates for each behavior profile
    for (uint32_t i = 0; i < m_default_n_sketches; ++i)
	{
		m_count_min_sketches.push_back(std::make_unique<plugin::anomalydetection::num::cms<uint64_t>>(m_default_gamma, m_default_eps));
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
            {ft::FTYPE_UINT64, "anomalydetection.count_min_sketch", "Count Min Sketch Estimate",
             "Count Min Sketch Estimate according to the specified behavior profile for a predefined set of {syscalls} events. Access different behavior profiles/sketches using indices. For instance, anomalydetection.count_min_sketch[0] retrieves the first behavior profile defined in the plugins' `init_config`."},
    };
    const int fields_size = sizeof(fields) / sizeof(fields[0]);
    static_assert(fields_size == ANOMALYDETECTION_FIELD_MAX, "Wrong number of anomalydetection fields.");
    return std::vector<falcosecurity::field_info>(fields, fields + fields_size);
}

bool anomalydetection::extract(const falcosecurity::extract_fields_input& in)
{
    auto& req = in.get_extract_request();
    uint64_t count_min_sketch_estimate = 0;
    switch(req.get_field_id())
    {
    case ANOMALYDETECTION_COUNT_MIN_SKETCH_COUNT:
        // Initial dev example
        count_min_sketch_estimate = m_count_min_sketches[0].get()->estimate(m_last_behavior_profile);
        req.set_value(count_min_sketch_estimate, true);
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

bool anomalydetection::parse_event(const falcosecurity::parse_event_input& in)
{
    auto& evt = in.get_event_reader();
    auto& tr = in.get_table_reader();
    falcosecurity::table_entry thread_entry;
    std::string tstr = "";
    m_last_behavior_profile.clear();

    // note: Plugin event parsing guaranteed to happen after libs' `sinsp_parser::process_event` has finished.
    // Needs to stay in sync w/ libs updates.
    // Ultimately gated by `base_syscalls` restrictions if Falco is used w/ `base_syscalls`.
    switch(evt.get_type())
    {
    // Falco rules `proc` use case: process / thread related profiling `spawned_process` macro
    case PPME_SYSCALL_EXECVE_19_X:
    case PPME_SYSCALL_EXECVEAT_X:
        {
            int64_t thread_id = in.get_event_reader().get_tid();
            if(thread_id <= 0)
            {
                return false;
            }
            try
            {
                thread_entry = m_thread_table.get_entry(tr, thread_id);
                // Initial dev example
                m_container_id.read_value(tr, thread_entry, m_last_behavior_profile);
                m_comm.read_value(tr, thread_entry, tstr);
                m_last_behavior_profile += tstr;
                m_count_min_sketches[0].get()->update(m_last_behavior_profile, (uint64_t)1);
            }
            catch(falcosecurity::plugin_exception e)
            {
                return false;
            }
            return true;
        }
    // Falco rules `fd` use cases 1: file open related profiling `open_write`, `open_read`, `open_file_failed` macros or evt.type=creat ...
    case PPME_SYSCALL_OPEN_X:
	case PPME_SYSCALL_CREAT_X:
	case PPME_SYSCALL_OPENAT_2_X:
	case PPME_SYSCALL_OPENAT2_X:
	case PPME_SYSCALL_OPEN_BY_HANDLE_AT_X:
    // Falco rules `fd` use cases 2: network related profiling `outbound`, `inbound`, `inbound_outbound` macros ...
    case PPME_SOCKET_SENDTO_X:
	case PPME_SOCKET_SENDMSG_X:
    case PPME_SOCKET_RECVFROM_X:
	case PPME_SOCKET_RECVMMSG_X:
    case PPME_SOCKET_CONNECT_X:
    case PPME_SOCKET_ACCEPT_X:
    case PPME_SOCKET_ACCEPT4_X:
    case PPME_SOCKET_LISTEN_X:
        return true;
    default:
        return false;
    }
}
