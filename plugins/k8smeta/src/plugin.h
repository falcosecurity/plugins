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

#include "plugin_only_consts.h"
#include "shared_with_tests_consts.h"
#include "grpc_client.h"

#include <thread>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <sstream>

struct resource_layout
{
    std::string uid;
    std::string kind;
    nlohmann::json meta;
    nlohmann::json spec;
    nlohmann::json status;
    nlohmann::json refs;

    std::string print_resource() const
    {
        std::ostringstream oss;
        oss << "Uid: " << uid << std::endl;
        oss << "Kind: " << kind << std::endl;
        oss << "Meta: " << meta << std::endl;
        oss << "Spec: " << spec << std::endl;
        oss << "Status: " << status << std::endl;
        oss << "Refs: " << refs << std::endl;
        return oss.str();
    }
};

struct sinsp_param
{
    uint16_t param_len;
    uint8_t* param_pointer;
};

class my_plugin
{
    public:
    // Keep this aligned with `get_fields`
    enum K8sFields
    {
        K8S_POD_NAME,
        K8S_POD_UID,
        K8S_POD_LABEL,
        K8S_POD_LABELS,
        K8S_POD_IP,
        K8S_NS_NAME,
        K8S_NS_UID,
        K8S_NS_LABEL,
        K8S_NS_LABELS,
        K8S_DEPLOYMENT_NAME,
        K8S_DEPLOYMENT_UID,
        K8S_DEPLOYMENT_LABEL,
        K8S_DEPLOYMENT_LABELS,
        K8S_SVC_NAME,
        K8S_SVC_UID,
        K8S_SVC_LABEL,
        K8S_SVC_LABELS,
        K8S_RS_NAME,
        K8S_RS_UID,
        K8S_RS_LABEL,
        K8S_RS_LABELS,
        K8S_RC_NAME,
        K8S_RC_UID,
        K8S_RC_LABEL,
        K8S_RC_LABELS,
        K8S_FIELD_MAX
    };

    enum K8sResource
    {
        POD,
        NS,
        DEPLOYMENT,
        SVC,
        RS,
        RC,
    };

    //////////////////////////
    // General plugin API
    //////////////////////////

    virtual ~my_plugin() = default;

    std::string get_name() { return PLUGIN_NAME; }

    std::string get_version() { return PLUGIN_VERSION; }

    std::string get_description() { return PLUGIN_DESCRIPTION; }

    std::string get_contact() { return PLUGIN_CONTACT; }

    std::string get_required_api_version()
    {
        return PLUGIN_REQUIRED_API_VERSION;
    }

    std::string get_last_error() { return m_lasterr; }

    void destroy() { SPDLOG_DEBUG("detach the plugin"); }

    falcosecurity::init_schema get_init_schema();

    void parse_init_config(nlohmann::json& config_json);

    bool init(falcosecurity::init_input& in);

    //////////////////////////
    // Async capability
    //////////////////////////

    std::vector<std::string> get_async_events() { return ASYNC_EVENT_NAMES; }

    std::vector<std::string> get_async_event_sources()
    {
        return ASYNC_EVENT_SOURCES;
    }

    bool start_async_events(
            std::shared_ptr<falcosecurity::async_event_handler_factory> f);

    bool stop_async_events() noexcept;

    void async_thread_loop(
            std::unique_ptr<falcosecurity::async_event_handler> h) noexcept;

    //////////////////////////
    // Extract capability
    //////////////////////////

    std::vector<std::string> get_extract_event_sources()
    {
        return EXTRACT_EVENT_SOURCES;
    }

    std::vector<falcosecurity::field_info> get_fields();

    bool inline get_uid_array(nlohmann::json& pod_refs_json,
                              enum K8sResource resource,
                              std::vector<std::string>& uid_array);

    bool inline get_layout(nlohmann::json& pod_refs_json,
                           enum K8sResource resource, resource_layout& layout);

    bool inline extract_name_from_meta(nlohmann::json& meta_json,
                                       falcosecurity::extract_request& req);

    bool inline extract_label_value_from_meta(
            nlohmann::json& meta_json, falcosecurity::extract_request& req);

    bool inline extract_labels_from_meta(nlohmann::json& meta_json,
                                         falcosecurity::extract_request& req);

    bool inline extract_uid_from_refs(nlohmann::json& pod_refs_json,
                                      enum K8sResource resource,
                                      falcosecurity::extract_request& req);

    bool inline extract_name_from_refs(nlohmann::json& pod_refs_json,
                                       enum K8sResource resource,
                                       falcosecurity::extract_request& req);

    bool inline extract_label_value_from_refs(
            nlohmann::json& pod_refs_json, enum K8sResource resource,
            falcosecurity::extract_request& req);

    bool inline extract_labels_from_refs(nlohmann::json& pod_refs_json,
                                         enum K8sResource resource,
                                         falcosecurity::extract_request& req);

    bool inline extract_uid_array_from_refs(
            nlohmann::json& pod_refs_json, enum K8sResource resource,
            falcosecurity::extract_request& req);

    bool inline extract_name_array_from_refs(
            nlohmann::json& pod_refs_json, enum K8sResource resource,
            falcosecurity::extract_request& req);

    bool inline extract_label_value_array_from_refs(
            nlohmann::json& pod_refs_json, enum K8sResource resource,
            falcosecurity::extract_request& req);

    bool inline extract_labels_array_from_refs(
            nlohmann::json& pod_refs_json, enum K8sResource resource,
            falcosecurity::extract_request& req);

    bool extract(const falcosecurity::extract_fields_input& in);

    //////////////////////////
    // Parse capability
    //////////////////////////

    // We need to parse only the async events produced by this plugin. The async
    // events produced by this plugin are injected in the syscall event source,
    // so here we need to parse events coming from the "syscall" source.
    // We will select specific events to parse through the
    // `get_parse_event_types` API.
    std::vector<std::string> get_parse_event_sources()
    {
        return PARSE_EVENT_SOURCES;
    }

    std::vector<falcosecurity::event_type> get_parse_event_types()
    {
        return PARSE_EVENT_CODES;
    }

    void inline parse_added_modified_resource(nlohmann::json& json_event,
                                              std::string& resource_uid,
                                              std::string& resource_kind);

    void inline parse_deleted_resource(nlohmann::json& json_event,
                                       std::string& resource_uid,
                                       std::string& resource_kind);

    bool inline parse_async_event(const falcosecurity::parse_event_input& in);

    bool inline extract_pod_uid(const falcosecurity::parse_event_input& in);

    bool parse_event(const falcosecurity::parse_event_input& in);

    private:
    // Async thread
    std::thread m_async_thread;
    std::atomic<bool> m_async_thread_quit;
    std::condition_variable m_cv;
    std::mutex m_mu;

    // Init params
    std::string m_collector_hostname;
    std::string m_collector_port;
    std::string m_node_name;
    std::string m_ca_PEM_encoding;

    // State tables
    std::unordered_map<std::string, resource_layout> m_pod_table;
    std::unordered_map<std::string, resource_layout> m_namespace_table;
    std::unordered_map<std::string, resource_layout> m_deployment_table;
    std::unordered_map<std::string, resource_layout> m_service_table;
    std::unordered_map<std::string, resource_layout> m_replicaset_table;
    std::unordered_map<std::string, resource_layout>
            m_replication_controller_table;
    std::unordered_map<std::string, resource_layout> m_deamonset_table;

    // Last error of the plugin
    std::string m_lasterr;
    // Accessor to the thread table
    falcosecurity::table m_thread_table;
    // Accessors to the fixed fields of the thread table
    falcosecurity::table_field m_pod_uid_field;
};

FALCOSECURITY_PLUGIN(my_plugin);
FALCOSECURITY_PLUGIN_FIELD_EXTRACTION(my_plugin);
FALCOSECURITY_PLUGIN_ASYNC_EVENTS(my_plugin);
FALCOSECURITY_PLUGIN_EVENT_PARSING(my_plugin);
