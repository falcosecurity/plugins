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

#include "consts.h"
#include "macros.h"
#include "matchers/matcher.h"
#include <unordered_map>
#include <unordered_set>

enum command_category
{
    CAT_NONE = 0,
    CAT_CONTAINER,
    CAT_HEALTHCHECK,
    CAT_LIVENESS_PROBE,
    CAT_READINESS_PROBE
};

class my_plugin
{
    public:
    //////////////////////////
    // General plugin API
    //////////////////////////

    virtual ~my_plugin() = default;

    std::string get_name();
    std::string get_version();
    std::string get_description();
    std::string get_contact();
    std::string get_required_api_version();
    std::string get_last_error();
    void destroy();
    falcosecurity::init_schema get_init_schema();
    void parse_init_config(nlohmann::json& config_json);
    bool init(falcosecurity::init_input& in);
    const std::vector<falcosecurity::metric>& get_metrics();

#ifdef _HAS_ASYNC
    //////////////////////////
    // Async capability
    //////////////////////////

    std::vector<std::string> get_async_events();
    std::vector<std::string> get_async_event_sources();
    bool start_async_events(
            std::shared_ptr<falcosecurity::async_event_handler_factory> f);
    bool stop_async_events() noexcept;
    void
    dump(std::unique_ptr<falcosecurity::async_event_handler> async_handler);
#endif

#ifdef _HAS_EXTRACT
    //////////////////////////
    // Extract capability
    //////////////////////////

    std::vector<std::string> get_extract_event_sources();
    std::vector<falcosecurity::field_info> get_fields();
    bool extract(const falcosecurity::extract_fields_input& in);
#endif

#ifdef _HAS_PARSE
    //////////////////////////
    // Parse capability
    //////////////////////////

    std::vector<std::string> get_parse_event_sources();
    std::vector<falcosecurity::event_type> get_parse_event_types();
    bool parse_async_event(const falcosecurity::parse_event_input& in);
    bool parse_container_event(const falcosecurity::parse_event_input& in);
    bool parse_container_json_event(const falcosecurity::parse_event_input& in);
    bool
    parse_container_json_2_event(const falcosecurity::parse_event_input& in);
    bool parse_new_process_event(const falcosecurity::parse_event_input& in);
    bool parse_event(const falcosecurity::parse_event_input& in);
#endif

#ifdef _HAS_LISTENING
    //////////////////////////
    // Listening capability
    //////////////////////////
    bool capture_open(const falcosecurity::capture_listen_input& in);
    bool capture_close(const falcosecurity::capture_listen_input& in);
#endif

    //////////////////////////
    // Helpers
    //////////////////////////
    void on_new_process(const falcosecurity::table_entry& thread_entry,
                        const falcosecurity::table_reader& tr,
                        const falcosecurity::table_writer& tw);
    std::string compute_container_id_for_thread(
            const falcosecurity::table_entry& thread_entry,
            const falcosecurity::table_reader& tr,
            std::shared_ptr<container_info>& info);
    void
    write_thread_category(const std::shared_ptr<const container_info>& cinfo,
                          const falcosecurity::table_entry& thread_entry,
                          const falcosecurity::table_reader& tr,
                          const falcosecurity::table_writer& tw);

    falcosecurity::_internal::ss_plugin_table_input& get_table();

    private:
    // State table
    std::unordered_map<std::string, std::shared_ptr<const container_info>>
            m_containers;
    // Last container enriched from an async event parsing.
    // Used to extract container info from aforementioned async events.
    std::shared_ptr<const container_info> m_last_container;
    // Cache being asked containers to go-worker through AskForContainerInfo()
    // API. Avoids repeatedly calling the API.
    std::unordered_set<std::string> m_asked_containers;

    std::vector<falcosecurity::metric> m_metrics;

    PluginConfig m_cfg;

    std::unique_ptr<matcher_manager> m_mgr;

    falcosecurity::logger m_logger;

    // Last error of the plugin
    std::string m_lasterr;
    // Accessor to the thread table
    falcosecurity::table m_threads_table;
    // Accessors to the thread table "pidns_init_start_ts" field
    falcosecurity::table_field m_threads_field_pidns_init_start_ts;
    // Accessors to the thread table "category" field
    falcosecurity::table_field m_threads_field_category;
    // Accessors to the thread table "vpid" field
    falcosecurity::table_field m_threads_field_vpid;
    // Accessors to the thread table "ptid" field
    falcosecurity::table_field m_threads_field_ptid;
    // Accessors to the thread table "args" sub table
    falcosecurity::table_field m_threads_field_args;
    // Accessors to the thread table "args" field values
    falcosecurity::table_field m_args_field;
    // Accessors to the thread table "exe" field
    falcosecurity::table_field m_threads_field_exe;
    // Accessors to the thread table "cgroups" table
    falcosecurity::table_field m_threads_field_cgroups;
    // Accessors to the thread table "cgroups" "second" field, ie: the cgroups
    // path
    falcosecurity::table_field m_cgroups_field_second;
    // Accessors to the thread table "container_id" foreign key field
    falcosecurity::table_field m_container_id_field;
};