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
#include "plugin.h"

#include <thread>
#include <atomic>
#include <chrono>
#include <unordered_map>
#include <sstream>
#include <re2/re2.h>
#include <fstream>

#define ADD_MODIFY_TABLE_ENTRY(_resource_name, _resource_table)                \
    if(resource_kind.compare(_resource_name) == 0)                             \
    {                                                                          \
        _resource_table[resource_uid] = res_layout;                            \
        /* In debug mode we just print which resource has been added/updated   \
         */                                                                    \
        SPDLOG_DEBUG("added/modified {} {}", _resource_name, resource_uid);    \
        /* In trace mode we print also the content of the resource */          \
        SPDLOG_TRACE("resource content {}", res_layout.print_resource());      \
        return;                                                                \
    }

#define DELETE_TABLE_ENTRY(_resource_name, _resource_table)                    \
    if(resource_kind.compare(_resource_name) == 0)                             \
    {                                                                          \
        _resource_table.erase(resource_uid);                                   \
        SPDLOG_DEBUG("deleted {} {}", _resource_name, resource_uid);           \
        return;                                                                \
    }

// This is the regex needed to extract the pod_uid from the cgroup
static re2::RE2 pattern(RGX_POD, re2::RE2::POSIX);

//////////////////////////
// General plugin API
//////////////////////////

falcosecurity::init_schema my_plugin::get_init_schema()
{
    /// todo!: check config names
    falcosecurity::init_schema init_schema;
    init_schema.schema_type =
            falcosecurity::init_schema_type::SS_PLUGIN_SCHEMA_JSON;
    init_schema.schema = R"(
{
	"$schema": "http://json-schema.org/draft-04/schema#",
	"required": [
		"collectorHostname",
		"collectorPort",
		"nodeName"
	],
	"properties": {
		"verbosity": {
			"enum": [
				"trace",
				"debug",
				"info",
				"warning",
				"error",
				"critical"
			],
			"title": "The plugin logging verbosity",
			"description": "The verbosity that the plugin will use when printing logs."
		},
		"collectorHostname": {
			"type": "string",
			"title": "The collector hostname",
			"description": "The hostname used by the plugin to contact the collector (e.g. '128.141.201.74')."
		},
		"collectorPort": {
			"type": "integer",
			"title": "The collector port",
			"description": "The port used by the plugin to contact the collector (e.g. '45000')."
		},
		"nodeName": {
			"type": "string",
			"title": "The node on which Falco is deployed",
			"description": "The plugin collects k8s metadata only for the node on which Falco is deployed so the node name must be specified."
		},
		"caPEMBundle": {
			"type": "string",
			"title": "The path to the PEM encoding of the server root certificates",
			"description": "The path to the PEM encoding of the server root certificates. E.g. '/etc/ssl/certs/ca-certificates.crt'"
		}
	},
	"additionalProperties": false,
	"type": "object"
})";
    return init_schema;
}

void my_plugin::parse_init_config(nlohmann::json& config_json)
{
    // Verbosity, the default verbosity is already set in the 'init' method
    if(config_json.contains(nlohmann::json::json_pointer(VERBOSITY_PATH)))
    {
        // If the user specified a verbosity we override the actual one (`info`)
        std::string verbosity;
        config_json.at(nlohmann::json::json_pointer(VERBOSITY_PATH))
                .get_to(verbosity);
        spdlog::set_level(spdlog::level::from_str(verbosity));
    }

    // Collector hostname
    if(config_json.contains(nlohmann::json::json_pointer(HOSTNAME_PATH)))
    {
        config_json.at(nlohmann::json::json_pointer(HOSTNAME_PATH))
                .get_to(m_collector_hostname);
    }
    else
    {
        // This should never happen since it is required by the json schema
        SPDLOG_CRITICAL("There is no collector hostname in the plugin config");
        assert(false);
    }

    // Collector port
    if(config_json.contains(nlohmann::json::json_pointer(PORT_PATH)))
    {
        uint64_t collector_port = 0;
        config_json.at(nlohmann::json::json_pointer(PORT_PATH))
                .get_to(collector_port);
        m_collector_port = std::to_string(collector_port);
    }
    else
    {
        // This should never happen since it is required by the json schema
        SPDLOG_CRITICAL("There is no collector port in the plugin config");
        assert(false);
    }

    // Node name
    if(config_json.contains(nlohmann::json::json_pointer(NODENAME_PATH)))
    {
        std::string nodename_string = "";
        config_json.at(nlohmann::json::json_pointer(NODENAME_PATH))
                .get_to(nodename_string);

        // todo!: remove it when we solved in Falco
        // This is just a simple workaround until we solve the Falco issue
        // If the provided string is an env variable we use the content
        // of the env variable
        std::string env_var = "";
        re2::RE2 env_var_pattern("(\\${[^}]+})", re2::RE2::POSIX);
        if(re2::RE2::PartialMatch(nodename_string, env_var_pattern, &env_var))
        {
            // - remove `${` at the beginning, so the start index is 2
            // - the total length is the length of the string -3 (`${}`)
            auto env_var_name = env_var.substr(2, env_var.length() - 3);
            if(getenv(env_var_name.c_str()))
            {
                m_node_name = getenv(env_var_name.c_str());
            }
            else
            {
                SPDLOG_CRITICAL("The provided env variable '{}' is empty",
                                env_var);
                m_node_name = "";
            }
        }
        else
        {
            m_node_name = nodename_string;
        }
        SPDLOG_DEBUG("metadata are received from node '{}'", m_node_name);
    }
    else
    {
        // This should never happen since it is required by the json schema
        SPDLOG_CRITICAL("There is no node name in the plugin config");
        assert(false);
    }

    // CA PEM path

    // Default case: insecure connection
    m_ca_PEM_encoding = "";
    if(config_json.contains(nlohmann::json::json_pointer(CA_CERT_PATH)))
    {
        std::string ca_PEM_encoding_path;
        config_json.at(nlohmann::json::json_pointer(CA_CERT_PATH))
                .get_to(ca_PEM_encoding_path);
        if(!ca_PEM_encoding_path.empty())
        {
            std::ifstream input_file(ca_PEM_encoding_path);
            if(!input_file.is_open())
            {
                SPDLOG_ERROR("Cannot open any PEM bundle at '{}'. Proceed with "
                             "insecure connection",
                             ca_PEM_encoding_path);
            }
            else
            {
                std::stringstream buffer;
                buffer << input_file.rdbuf();
                m_ca_PEM_encoding = buffer.str();
            }
        }
    }
}

bool my_plugin::init(falcosecurity::init_input& in)
{
    using st = falcosecurity::state_value_type;
    auto& t = in.tables();

    // The default logger is already multithread.
    // The initial verbosity is `info`, after parsing the plugin config, this
    // value could change
    spdlog::set_level(spdlog::level::info);

    // Alternatives logs:
    // spdlog::set_pattern("%a %b %d %X %Y: [%l] [k8smeta] %v");
    //
    // We use local time like in Falco, not UTC
    spdlog::set_pattern("%c: [%l] [k8smeta] %v");

    // This should never happen, the config is validated by the framework
    if(in.get_config().empty())
    {
        m_lasterr = "cannot find the init config for the plugin";
        SPDLOG_CRITICAL(m_lasterr);
        return false;
    }

    auto cfg = nlohmann::json::parse(in.get_config());
    parse_init_config(cfg);

    SPDLOG_DEBUG("init the plugin");

    // Remove this log when we reach `1.0.0`
    SPDLOG_WARN("[EXPERIMENTAL] This plugin is in active development "
                "and may undergo changes in behavior without prioritizing "
                "backward compatibility.");

    try
    {
        m_thread_table = t.get_table(THREAD_TABLE_NAME, st::SS_PLUGIN_ST_INT64);
        // Add the pod_uid field into thread table
        m_pod_uid_field = m_thread_table.add_field(
                t.fields(), POD_UID_FIELD_NAME, st::SS_PLUGIN_ST_STRING);
    }
    catch(falcosecurity::plugin_exception e)
    {
        m_lasterr = "cannot add the '" + std::string(POD_UID_FIELD_NAME) +
                    "' field into the '" + std::string(THREAD_TABLE_NAME) +
                    "' table: " + e.what();
        SPDLOG_CRITICAL(m_lasterr);
        return false;
    }
    return true;
}

//////////////////////////
// Async capability
//////////////////////////

// We need this API to start the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::start_async_events(
        std::shared_ptr<falcosecurity::async_event_handler_factory> f)
{
    m_async_thread_quit = false;
    m_async_thread = std::thread(&my_plugin::async_thread_loop, this,
                                 std::move(f->new_handler()));
    return true;
}

// We need this API to stop the async thread when the
// `set_async_event_handler` plugin API will be called.
bool my_plugin::stop_async_events() noexcept
{
    {
        std::unique_lock<std::mutex> l(m_mu);
        m_async_thread_quit = true;
        m_cv.notify_one();
        // Release the lock
    }

    if(m_async_thread.joinable())
    {
        m_async_thread.join();
        SPDLOG_DEBUG("joined the async thread");
    }
    return true;
}

// This is not a needed API is just a custom method we want to use
// internally.
void my_plugin::async_thread_loop(
        std::unique_ptr<falcosecurity::async_event_handler> h) noexcept
{
    std::string ip_port = m_collector_hostname + ":" + m_collector_port;
    uint64_t backoff_seconds = MIN_BACKOFF_VALUE;

    while(!m_async_thread_quit.load())
    {
        K8sMetaClient k8sclient(m_node_name, ip_port, m_ca_PEM_encoding, m_mu,
                                m_cv, m_async_thread_quit, *h.get());

        if(!k8sclient.Await(backoff_seconds))
        {
            break;
        }

        SPDLOG_INFO("Retry after '{}' seconds", backoff_seconds);
        std::unique_lock<std::mutex> l(m_mu);
        m_cv.wait_for(l, std::chrono::seconds(backoff_seconds),
                      [this] { return m_async_thread_quit.load(); });
    }

    SPDLOG_INFO("Async thread terminated");
}

//////////////////////////
// Extract capability
//////////////////////////

std::vector<falcosecurity::field_info> my_plugin::get_fields()
{
    using ft = falcosecurity::field_value_type;
    // Use an array to perform a static_assert one the size.
    const falcosecurity::field_info fields[] = {
            {ft::FTYPE_STRING, "k8smeta.pod.name", "Pod Name",
             "Kubernetes pod name."},
            {ft::FTYPE_STRING, "k8smeta.pod.uid", "Pod UID",
             "Kubernetes pod UID."},
            {ft::FTYPE_STRING,
             "k8smeta.pod.label",
             "Pod Label",
             "Kubernetes pod label. E.g. 'k8smeta.pod.label[foo]'.",
             {.key = true, .required = true}},
            {ft::FTYPE_STRING, "k8smeta.pod.labels", "Pod Labels",
             "Kubernetes pod comma-separated key/value labels. E.g. "
             "'(foo1:bar1,foo2:bar2)'.",
             falcosecurity::field_arg(), true},
            {ft::FTYPE_STRING, "k8smeta.pod.ip", "Pod Ip", "Kubernetes pod ip"},

            {ft::FTYPE_STRING, "k8smeta.ns.name", "Namespace Name",
             "Kubernetes namespace name."},
            {ft::FTYPE_STRING, "k8smeta.ns.uid", "Namespace UID",
             "Kubernetes namespace UID."},
            {ft::FTYPE_STRING,
             "k8smeta.ns.label",
             "Namespace Label",
             "Kubernetes namespace label. E.g. 'k8smeta.ns.label[foo]'.",
             {.key = true, .index = false, .required = true}},
            {ft::FTYPE_STRING, "k8smeta.ns.labels", "Namespace Labels",
             "Kubernetes namespace comma-separated key/value labels. E.g. "
             "'(foo1:bar1,foo2:bar2)'.",
             falcosecurity::field_arg(), true},

            {ft::FTYPE_STRING, "k8smeta.deployment.name", "Deployment Name",
             "Kubernetes deployment name."},
            {ft::FTYPE_STRING, "k8smeta.deployment.uid", "Deployment UID",
             "Kubernetes deployment UID."},
            {ft::FTYPE_STRING,
             "k8smeta.deployment.label",
             "Deployment Label",
             "Kubernetes deployment label. E.g. 'k8smeta.rs.label[foo]'.",
             {.key = true, .required = true}},
            {ft::FTYPE_STRING, "k8smeta.deployment.labels", "Deployment Labels",
             "Kubernetes deployment comma-separated key/value labels. E.g. "
             "'(foo1:bar1,foo2:bar2)'.",
             falcosecurity::field_arg(), true},

            {ft::FTYPE_STRING, "k8smeta.svc.name", "Services Name",
             "Kubernetes services name. Return a list with all the names of "
             "the services associated with the "
             "current pod. E.g. '(service1,service2)'",
             falcosecurity::field_arg(), true},
            {ft::FTYPE_STRING, "k8smeta.svc.uid", "Services UID",
             "Kubernetes services UID. Return a list with all the UIDs of the "
             "services associated with the "
             "current pod. E.g. "
             "'(88279776-941c-491e-8da1-95ef30f50fe8,149e72f4-a570-4282-bfa0-"
             "25307c5007e8)'",
             falcosecurity::field_arg(), true},
            {ft::FTYPE_STRING,
             "k8smeta.svc.label",
             "Services Label",
             "Kubernetes services label. If the services associated with the "
             "current pod have a label with this "
             "name, return the list of label's values. E.g. if the current pod "
             "has 2 services associated and both "
             "have the 'foo' label, 'k8smeta.svc.label[foo]' will return "
             "'(service1-label-value,service2-label-value)",
             {.key = true, .required = true},
             true},
            {ft::FTYPE_STRING, "k8smeta.svc.labels", "Services Labels",
             "Kubernetes services labels. Return a list with all the "
             "comma-separated key/value labels of the "
             "services associated with the current pod. E.g. "
             "'(foo1:bar1,foo2:bar2)'",
             falcosecurity::field_arg(), true},

            {ft::FTYPE_STRING, "k8smeta.rs.name", "Replica Set Name",
             "Kubernetes replica set name."},
            {ft::FTYPE_STRING, "k8smeta.rs.uid", "Replica Set UID",
             "Kubernetes replica set UID."},
            {ft::FTYPE_STRING,
             "k8smeta.rs.label",
             "Replica Set Label",
             "Kubernetes replica set label. E.g. 'k8smeta.rs.label[foo]'.",
             {.key = true, .required = true}},
            {ft::FTYPE_STRING, "k8smeta.rs.labels", "Replica Set Labels",
             "Kubernetes replica set comma-separated key/value labels. E.g. "
             "'(foo1:bar1,foo2:bar2)'.",
             falcosecurity::field_arg(), true},

            {ft::FTYPE_STRING, "k8smeta.rc.name", "Replication Controller Name",
             "Kubernetes replication controller name."},
            {ft::FTYPE_STRING, "k8smeta.rc.uid", "Replication Controller UID",
             "Kubernetes replication controller UID."},
            {ft::FTYPE_STRING,
             "k8smeta.rc.label",
             "Replication Controller Label",
             "Kubernetes replication controller label. E.g. "
             "'k8smeta.rc.label[foo]'.",
             {.key = true, .required = true}},
            {ft::FTYPE_STRING, "k8smeta.rc.labels",
             "Replication Controller Labels",
             "Kubernetes replication controller comma-separated key/value "
             "labels. E.g. '(foo1:bar1,foo2:bar2)'.",
             falcosecurity::field_arg(), true},
    };
    const int fields_size = sizeof(fields) / sizeof(fields[0]);
    static_assert(fields_size == K8S_FIELD_MAX, "Wrong number of k8s fields.");
    return std::vector<falcosecurity::field_info>(fields, fields + fields_size);
}

bool inline my_plugin::get_uid_array(nlohmann::json& pod_refs_json,
                                     enum K8sResource resource,
                                     std::vector<std::string>& uid_array)
{
    std::string json_path = "";
    switch(resource)
    {
    case NS:
        json_path = "/resources/Namespace/list";
        break;

    case DEPLOYMENT:
        json_path = "/resources/Deployment/list";
        break;

    case SVC:
        json_path = "/resources/Service/list";
        break;

    case RS:
        json_path = "/resources/ReplicaSet/list";
        break;

    case RC:
        json_path = "/resources/ReplicationController/list";
        break;

    default:
        return false;
    }
    if(!pod_refs_json.contains(nlohmann::json::json_pointer(json_path)))
    {
        return false;
    }
    pod_refs_json.at(nlohmann::json::json_pointer(json_path)).get_to(uid_array);

    // If the `contains()` is successful we should always have at least one
    // element, this is an extra check.
    if(uid_array.empty())
    {
        return false;
    }

    return true;
}

bool inline my_plugin::get_layout(nlohmann::json& pod_refs_json,
                                  enum K8sResource resource,
                                  resource_layout& layout)
{
    std::vector<std::string> uid_array;
    if(!get_uid_array(pod_refs_json, resource, uid_array))
    {
        return false;
    }

    std::unordered_map<std::string, resource_layout> table;
    switch(resource)
    {
    case NS:
        table = m_namespace_table;
        break;

    case DEPLOYMENT:
        table = m_deployment_table;
        break;

    case SVC:
        table = m_service_table;
        break;

    case RS:
        table = m_replicaset_table;
        break;

    case RC:
        table = m_replication_controller_table;
        break;

    default:
        return false;
    }

    auto it = table.find(uid_array[0]);
    if(it == table.end())
    {
        return false;
    }
    layout = it->second;
    return true;
}

bool inline my_plugin::extract_name_from_meta(
        nlohmann::json& meta_json, falcosecurity::extract_request& req)
{
    std::string resource_name;
    // todo! Possible optimization here and in some other places, some paths
    // should always be there.
    if(!meta_json.contains(nlohmann::json::json_pointer(NAME_PATH)))
    {
        SPDLOG_ERROR("The resource meta doesn't contain the '{}' field. "
                     "Resource meta:\n{}\n",
                     NAME_PATH, meta_json.dump());
        return false;
    }
    meta_json.at(nlohmann::json::json_pointer(NAME_PATH)).get_to(resource_name);
    req.set_value(resource_name, true);
    return true;
}

bool inline my_plugin::extract_label_value_from_meta(
        nlohmann::json& meta_json, falcosecurity::extract_request& req)
{
    if(!req.is_arg_present())
    {
        return false;
    }

    // We cannot concatenate "/labels/<label_key>" to extract the label value
    // because `<label_key>` can contain `/` (`app.kubernetes.io/component`), so
    // no json paths! We fetch the whole map and then we iterate over it.
    std::unordered_map<std::string, std::string> labels_map;
    if(!meta_json.contains(nlohmann::json::json_pointer(LABELS_PATH)))
    {
        // Please note that this is not an error, is possible that
        // some resources don't have the `/labels` key.
        return false;
    }
    meta_json.at(nlohmann::json::json_pointer(LABELS_PATH)).get_to(labels_map);

    auto it = labels_map.find(req.get_arg_key());
    if(it == labels_map.end())
    {
        return false;
    }
    req.set_value(it->second, true);
    return true;
}

bool inline my_plugin::extract_labels_from_meta(
        nlohmann::json& meta_json, falcosecurity::extract_request& req)
{
    std::unordered_map<std::string, std::string> labels_map;
    if(!meta_json.contains(nlohmann::json::json_pointer(LABELS_PATH)))
    {
        // Please note that this is not an error, is possible that
        // some resources don't have the `/labels` key.
        return false;
    }
    meta_json.at(nlohmann::json::json_pointer(LABELS_PATH)).get_to(labels_map);

    std::vector<std::string> labels;
    for(const auto label : labels_map)
    {
        labels.emplace_back(label.first + ":" + label.second);
    }

    if(labels.empty())
    {
        return false;
    }

    req.set_value(labels.begin(), labels.end(), true);
    return true;
}

bool inline my_plugin::extract_uid_from_refs(
        nlohmann::json& pod_refs_json, enum K8sResource resource,
        falcosecurity::extract_request& req)
{
    std::vector<std::string> uid_array;
    if(!get_uid_array(pod_refs_json, resource, uid_array))
    {
        return false;
    }

    // We have at least one element otherwise the previous check should return
    // 0.
    req.set_value(uid_array[0], true);
    return true;
}

bool inline my_plugin::extract_name_from_refs(
        nlohmann::json& pod_refs_json, enum K8sResource resource,
        falcosecurity::extract_request& req)
{
    resource_layout rs_layout;
    if(!get_layout(pod_refs_json, resource, rs_layout))
    {
        return false;
    }
    return extract_name_from_meta(rs_layout.meta, req);
}

bool inline my_plugin::extract_label_value_from_refs(
        nlohmann::json& pod_refs_json, enum K8sResource resource,
        falcosecurity::extract_request& req)
{
    resource_layout rs_layout;
    if(!get_layout(pod_refs_json, resource, rs_layout))
    {
        return false;
    }
    return extract_label_value_from_meta(rs_layout.meta, req);
}

bool inline my_plugin::extract_labels_from_refs(
        nlohmann::json& pod_refs_json, enum K8sResource resource,
        falcosecurity::extract_request& req)
{
    resource_layout rs_layout;
    if(!get_layout(pod_refs_json, resource, rs_layout))
    {
        return false;
    }

    return extract_labels_from_meta(rs_layout.meta, req);
}

bool inline my_plugin::extract_uid_array_from_refs(
        nlohmann::json& pod_refs_json, enum K8sResource resource,
        falcosecurity::extract_request& req)
{
    std::vector<std::string> uid_array;
    if(!get_uid_array(pod_refs_json, resource, uid_array))
    {
        return false;
    }

    req.set_value(uid_array.begin(), uid_array.end(), true);
    return true;
}

bool inline my_plugin::extract_name_array_from_refs(
        nlohmann::json& pod_refs_json, enum K8sResource resource,
        falcosecurity::extract_request& req)
{
    std::vector<std::string> uid_array;
    if(!get_uid_array(pod_refs_json, resource, uid_array))
    {
        return false;
    }

    std::unordered_map<std::string, resource_layout> table;
    switch(resource)
    {
    case NS:
        table = m_namespace_table;
        break;

    case DEPLOYMENT:
        table = m_deployment_table;
        break;

    case SVC:
        table = m_service_table;
        break;

    case RS:
        table = m_replicaset_table;
        break;

    case RC:
        table = m_replication_controller_table;
        break;

    default:
        return false;
    }

    std::vector<std::string> name_array;
    std::string name;
    for(const auto& uid : uid_array)
    {
        auto it = table.find(uid);
        if(it == table.end())
        {
            continue;
        }

        if(!it->second.meta.contains(nlohmann::json::json_pointer(NAME_PATH)))
        {
            SPDLOG_ERROR("The resource meta doesn't contain the '{}' field. "
                         "Resource meta:\n{}\n",
                         NAME_PATH, it->second.meta.dump());
            return false;
        }
        it->second.meta.at(nlohmann::json::json_pointer(NAME_PATH))
                .get_to(name);
        name_array.push_back(name);
    }

    if(name_array.empty())
    {
        return false;
    }

    req.set_value(name_array.begin(), name_array.end(), true);
    return true;
}

bool inline my_plugin::extract_label_value_array_from_refs(
        nlohmann::json& pod_refs_json, enum K8sResource resource,
        falcosecurity::extract_request& req)
{
    if(!req.is_arg_present())
    {
        return false;
    }

    std::vector<std::string> uid_array;
    if(!get_uid_array(pod_refs_json, resource, uid_array))
    {
        return false;
    }

    std::unordered_map<std::string, resource_layout> table;
    switch(resource)
    {
    case NS:
        table = m_namespace_table;
        break;

    case DEPLOYMENT:
        table = m_deployment_table;
        break;

    case SVC:
        table = m_service_table;
        break;

    case RS:
        table = m_replicaset_table;
        break;

    case RC:
        table = m_replication_controller_table;
        break;

    default:
        return false;
    }

    std::vector<std::string> label_value_array;
    std::string label_value;
    std::unordered_map<std::string, std::string> labels_map;
    for(const auto& uid : uid_array)
    {
        auto layout_it = table.find(uid);
        if(layout_it == table.end())
        {
            continue;
        }

        // If the resource doesn't have a `/labels` field skip it.
        if(!layout_it->second.meta.contains(
                   nlohmann::json::json_pointer(LABELS_PATH)))
        {
            continue;
        }

        layout_it->second.meta.at(nlohmann::json::json_pointer(LABELS_PATH))
                .get_to(labels_map);
        auto it = labels_map.find(req.get_arg_key());
        if(it == labels_map.end())
        {
            continue;
        }
        label_value_array.push_back(it->second);
    }

    if(label_value_array.empty())
    {
        return false;
    }

    req.set_value(label_value_array.begin(), label_value_array.end(), true);
    return true;
}

bool inline my_plugin::extract_labels_array_from_refs(
        nlohmann::json& pod_refs_json, enum K8sResource resource,
        falcosecurity::extract_request& req)
{
    std::vector<std::string> uid_array;
    if(!get_uid_array(pod_refs_json, resource, uid_array))
    {
        return false;
    }

    std::unordered_map<std::string, resource_layout> table;
    switch(resource)
    {
    case NS:
        table = m_namespace_table;
        break;

    case DEPLOYMENT:
        table = m_deployment_table;
        break;

    case SVC:
        table = m_service_table;
        break;

    case RS:
        table = m_replicaset_table;
        break;

    case RC:
        table = m_replication_controller_table;
        break;

    default:
        return false;
    }

    std::vector<std::string> labels_array;
    std::unordered_map<std::string, std::string> labels_map;
    for(const auto& uid : uid_array)
    {
        auto layout_it = table.find(uid);
        if(layout_it == table.end())
        {
            continue;
        }

        // If the resource doesn't have a `/labels` field skip it.
        if(!layout_it->second.meta.contains(
                   nlohmann::json::json_pointer(LABELS_PATH)))
        {
            continue;
        }

        layout_it->second.meta.at(nlohmann::json::json_pointer(LABELS_PATH))
                .get_to(labels_map);
        for(const auto label : labels_map)
        {
            labels_array.emplace_back(label.first + ":" + label.second);
        }
    }

    if(labels_array.empty())
    {
        return false;
    }

    req.set_value(labels_array.begin(), labels_array.end(), true);
    return true;
}

bool my_plugin::extract(const falcosecurity::extract_fields_input& in)
{
    auto& req = in.get_extract_request();
    auto& tr = in.get_table_reader();

    int64_t thread_id = in.get_event_reader().get_tid();

    if(thread_id <= 0)
    {
        SPDLOG_INFO("unknown thread id for event num '{}' with type '{}'",
                    in.get_event_reader().get_num(),
                    int32_t(in.get_event_reader().get_type()));
        return false;
    }

    falcosecurity::table_entry thread_entry;
    std::string pod_uid = "";
    try
    {
        // retrieve the thread entry associated with this thread id
        thread_entry = m_thread_table.get_entry(tr, thread_id);
        // retrieve pod_uid from the entry
        m_pod_uid_field.read_value(tr, thread_entry, pod_uid);
    }
    catch(falcosecurity::plugin_exception e)
    {
        SPDLOG_ERROR("cannot extract the pod uid for the thread id '{}': {}",
                     thread_id, e.what());
        return false;
    }

    // The process is not into a pod, stop here.
    if(pod_uid.empty())
    {
        return false;
    }

    // Try to find the entry associated with the pod_uid
    auto it = m_pod_table.find(pod_uid);
    if(it == m_pod_table.end())
    {
        SPDLOG_DEBUG("the plugin has no info for the pod uid '{}'", pod_uid);
        return false;
    }

    auto pod_layout = it->second;
    switch(req.get_field_id())
    {
    case K8S_POD_NAME:
        return extract_name_from_meta(pod_layout.meta, req);
    case K8S_POD_UID:
        req.set_value(pod_uid, true);
        break;
    case K8S_POD_LABEL:
        return extract_label_value_from_meta(pod_layout.meta, req);
    case K8S_POD_LABELS:
        return extract_labels_from_meta(pod_layout.meta, req);
    case K8S_POD_IP:
    {
        // The pod ip is not always there, for example during pod
        // initialization we could receive an initial pod without the ip and
        // then in a second moment, we will receive an update on that pod.
        if(!pod_layout.status.contains(
                   nlohmann::json::json_pointer(POD_IP_PATH)))
        {
            return false;
        }
        std::string pod_ip;
        pod_layout.status.at(nlohmann::json::json_pointer(POD_IP_PATH))
                .get_to(pod_ip);
        req.set_value(pod_ip, true);
        break;
    }
    case K8S_NS_NAME:
    {
        if(!pod_layout.meta.contains(
                   nlohmann::json::json_pointer(NAMESPACE_PATH)))
        {
            SPDLOG_ERROR("The pod meta doesn't contain the '{}' field. "
                         "Resource meta:\n{}\n",
                         NAMESPACE_PATH, pod_layout.meta.dump());
            return false;
        }
        std::string pod_namespace_name = "";
        pod_layout.meta.at(nlohmann::json::json_pointer(NAMESPACE_PATH))
                .get_to(pod_namespace_name);
        req.set_value(pod_namespace_name, true);
        break;
    }
    case K8S_NS_UID:
        return extract_uid_from_refs(pod_layout.refs, NS, req);
    case K8S_NS_LABEL:
        return extract_label_value_from_refs(pod_layout.refs, NS, req);
    case K8S_NS_LABELS:
        return extract_labels_from_refs(pod_layout.refs, NS, req);
        // We cannot extract deployment fields directly from the pod name
        // because it's possible to move some pods from one deployment to
        // another under some circumstances.
    case K8S_DEPLOYMENT_NAME:
        return extract_name_from_refs(pod_layout.refs, DEPLOYMENT, req);
    case K8S_DEPLOYMENT_UID:
        return extract_uid_from_refs(pod_layout.refs, DEPLOYMENT, req);
    case K8S_DEPLOYMENT_LABEL:
        return extract_label_value_from_refs(pod_layout.refs, DEPLOYMENT, req);
    case K8S_DEPLOYMENT_LABELS:
        return extract_labels_from_refs(pod_layout.refs, DEPLOYMENT, req);
    case K8S_SVC_NAME:
        return extract_name_array_from_refs(pod_layout.refs, SVC, req);
    case K8S_SVC_UID:
        return extract_uid_array_from_refs(pod_layout.refs, SVC, req);
    case K8S_SVC_LABEL:
        return extract_label_value_array_from_refs(pod_layout.refs, SVC, req);
    case K8S_SVC_LABELS:
        return extract_labels_array_from_refs(pod_layout.refs, SVC, req);
        // We cannot extract replicaSet fields directly from the pod name
        // because it's possible to move some pods from one replicaSet to
        // another under some circumstances.
    case K8S_RS_NAME:
        return extract_name_from_refs(pod_layout.refs, RS, req);
    case K8S_RS_UID:
        return extract_uid_from_refs(pod_layout.refs, RS, req);
    case K8S_RS_LABEL:
        return extract_label_value_from_refs(pod_layout.refs, RS, req);
    case K8S_RS_LABELS:
        return extract_labels_from_refs(pod_layout.refs, RS, req);
        // We cannot extract replicationController fields directly from the pod
        // name because it's possible to move some pods from one
        // replicationController to another under some circumstances.
    case K8S_RC_NAME:
        return extract_name_from_refs(pod_layout.refs, RC, req);
    case K8S_RC_UID:
        return extract_uid_from_refs(pod_layout.refs, RC, req);
    case K8S_RC_LABEL:
        return extract_label_value_from_refs(pod_layout.refs, RC, req);
    case K8S_RC_LABELS:
        return extract_labels_from_refs(pod_layout.refs, RC, req);

    default:
        SPDLOG_ERROR(
                "unknown extraction request on field '{}' for pod_uid '{}'",
                req.get_field_id(), pod_uid);
        return false;
    }

    return true;
}

//////////////////////////
// Parse capability
//////////////////////////

void inline my_plugin::parse_added_modified_resource(nlohmann::json& json_event,
                                                     std::string& resource_uid,
                                                     std::string& resource_kind)
{
    // We craft the resource layout
    resource_layout res_layout = {
            .uid = resource_uid,
            .kind = resource_kind,
    };

    if(json_event.contains(nlohmann::json::json_pointer(META_PATH)))
    {
        std::string meta_string;
        json_event.at(nlohmann::json::json_pointer(META_PATH))
                .get_to(meta_string);
        res_layout.meta = nlohmann::json::parse(meta_string);
    }

    if(json_event.contains(nlohmann::json::json_pointer(SPEC_PATH)))
    {
        std::string spec_string;
        json_event.at(nlohmann::json::json_pointer(SPEC_PATH))
                .get_to(spec_string);
        res_layout.spec = nlohmann::json::parse(spec_string);
    }

    if(json_event.contains(nlohmann::json::json_pointer(STATUS_PATH)))
    {
        std::string status_string;
        json_event.at(nlohmann::json::json_pointer(STATUS_PATH))
                .get_to(status_string);
        res_layout.status = nlohmann::json::parse(status_string);
    }

    if(json_event.contains(nlohmann::json::json_pointer(REFS_PATH)))
    {
        nlohmann::json refs_json;
        json_event.at(nlohmann::json::json_pointer(REFS_PATH))
                .get_to(refs_json);
        res_layout.refs = refs_json;
    }

    ADD_MODIFY_TABLE_ENTRY("Pod", m_pod_table)
    ADD_MODIFY_TABLE_ENTRY("Namespace", m_namespace_table)
    ADD_MODIFY_TABLE_ENTRY("Deployment", m_deployment_table)
    ADD_MODIFY_TABLE_ENTRY("Service", m_service_table)
    ADD_MODIFY_TABLE_ENTRY("ReplicaSet", m_replicaset_table)
    ADD_MODIFY_TABLE_ENTRY("ReplicationController",
                           m_replication_controller_table)
    ADD_MODIFY_TABLE_ENTRY("DeamonSet", m_deamonset_table)
}

void inline my_plugin::parse_deleted_resource(nlohmann::json& json_event,
                                              std::string& resource_uid,
                                              std::string& resource_kind)
{
    DELETE_TABLE_ENTRY("Pod", m_pod_table)
    DELETE_TABLE_ENTRY("Namespace", m_namespace_table)
    DELETE_TABLE_ENTRY("Deployment", m_deployment_table)
    DELETE_TABLE_ENTRY("Service", m_service_table)
    DELETE_TABLE_ENTRY("ReplicaSet", m_replicaset_table)
    DELETE_TABLE_ENTRY("ReplicationController", m_replication_controller_table)
    DELETE_TABLE_ENTRY("DeamonSet", m_deamonset_table)
}

bool inline my_plugin::parse_async_event(
        const falcosecurity::parse_event_input& in)
{
    auto& evt = in.get_event_reader();
    falcosecurity::events::asyncevent_e_decoder ad(evt);
    if(std::strcmp(ad.get_name(), ASYNC_EVENT_NAME) != 0)
    {
        // We are not interested in parsing async events that are not
        // generated by our plugin.
        // This is not an error, it could happen when we have more than one
        // async plugin loaded.
        SPDLOG_DEBUG("received an sync event with name {}", ad.get_name());
        return true;
    }

    uint32_t json_charbuf_len = 0;
    char* json_charbuf_pointer = (char*)ad.get_data(json_charbuf_len);
    if(json_charbuf_pointer == nullptr)
    {
        m_lasterr = "there is no payload in the async event";
        SPDLOG_ERROR(m_lasterr);
        return false;
    }
    auto json_event = nlohmann::json::parse(std::string(json_charbuf_pointer));

    std::string event_reason;
    std::string resource_uid;
    std::string resource_kind;

    if(!json_event.contains(nlohmann::json::json_pointer(REASON_PATH)) ||
       !json_event.contains(nlohmann::json::json_pointer(UID_PATH)) ||
       !json_event.contains(nlohmann::json::json_pointer(KIND_PATH)))
    {
        SPDLOG_ERROR("Invalid json resource.'{}', '{}', and '{}' should always "
                     "be present. Resource json:\n{}\n",
                     REASON_PATH, UID_PATH, KIND_PATH, json_event.dump());
        return false;
    }

    json_event.at(nlohmann::json::json_pointer(REASON_PATH))
            .get_to(event_reason);
    json_event.at(nlohmann::json::json_pointer(UID_PATH)).get_to(resource_uid);
    json_event.at(nlohmann::json::json_pointer(KIND_PATH))
            .get_to(resource_kind);

    if(event_reason.compare(REASON_CREATE) == 0)
    {
        SPDLOG_DEBUG("try to add {} '{}'", resource_kind, resource_uid);
        parse_added_modified_resource(json_event, resource_uid, resource_kind);
    }
    else if(event_reason.compare(REASON_UPDATE) == 0)
    {
        SPDLOG_DEBUG("try to update {} '{}'", resource_kind, resource_uid);
        parse_added_modified_resource(json_event, resource_uid, resource_kind);
    }
    else if(event_reason.compare(REASON_DELETE) == 0)
    {
        SPDLOG_DEBUG("try to delete {} '{}'", resource_kind, resource_uid);
        parse_deleted_resource(json_event, resource_uid, resource_kind);
    }
    else
    {
        SPDLOG_ERROR("reason '{}' is not known to the plugin", event_reason);
        return false;
    }
    return true;
}

// Obtain a param from a sinsp event
static inline sinsp_param get_syscall_evt_param(void* evt, uint32_t num_param)
{
    uint32_t dataoffset = 0;
    // pointer to the lengths array inside the event.
    auto len = (uint16_t*)((uint8_t*)evt +
                           sizeof(falcosecurity::_internal::ss_plugin_event));
    for(uint32_t j = 0; j < num_param; j++)
    {
        // sum lengths of the previous params.
        dataoffset += len[j];
    }
    return {.param_len = len[num_param],
            .param_pointer =
                    ((uint8_t*)&len
                             [((falcosecurity::_internal::ss_plugin_event*)evt)
                                      ->nparams]) +
                    dataoffset};
}

bool inline my_plugin::extract_pod_uid(
        const falcosecurity::parse_event_input& in)
{
    auto res_param = get_syscall_evt_param(in.get_event_reader().get_buf(),
                                           EXECVE_CLONE_RES_PARAM_IDX);

    // - For execve/execveat we exclude failed syscall events
    // - For clone/fork/clone3 we exclude failed syscall events (ret<0) and
    // caller events (ret>0).
    //   When the new thread is in a container in libsinsp we only parse the
    //   child exit event, so we can do the same thing here. In the child the
    //   return value is `0`.
    if(*((uint64_t*)(res_param.param_pointer)) != 0)
    {
        return false;
    }

    /// todo! Possible optimization, we can set the pod_uid only if we are in a
    /// container
    // but we need to access the `m_flags` field to understand if we are in a
    // container or not. It's also true that if we enable this plugin we are in
    // a k8s environment so we need to evaluate this.

    // Extract cgroup param
    auto cgroup_param = get_syscall_evt_param(in.get_event_reader().get_buf(),
                                              EXECVE_CLONE_CGROUP_PARAM_IDX);

    // If croups are empty we don't parse the event
    if(cgroup_param.param_len == 0)
    {
        return false;
    }

    // Our cgroup an array of charbufs `\0`-termiated. The first charbuf could
    // be something like this:
    // cpuset=/kubelet.slice/kubelet-kubepods.slice/kubelet-kubepods-pod05869489-8c7f-45dc-9abd-1b1620787bb1.slice/cri-containerd-2f92446a3fbfd0b7a73457b45e96c75a25c5e44e7b1bcec165712b906551c261.scope\0
    // So we can put it in a string and apply our regex.
    std::string cgroup_first_charbuf = (char*)cgroup_param.param_pointer;

    // We set the pod uid to `""` if we are not able to extract it.
    std::string pod_uid = "";

    if(re2::RE2::PartialMatch(cgroup_first_charbuf, pattern, &pod_uid))
    {
        // Here `pod_uid` could have 2 possible layouts:
        // - (driver cgroup) pod05869489-8c7f-45dc-9abd-1b1620787bb1
        // - (driver systemd) pod05869489_8c7f_45dc_9abd_1b1620787bb1

        // As a first thing we remove the "pod" prefix from `pod_uid`
        pod_uid.erase(0, 3);

        // Then we convert `_` into `-` if we are in `systemd` notation.
        // The final `pod_uid` layout will be:
        // 05869489-8c7f-45dc-9abd-1b1620787bb1
        std::replace(pod_uid.begin(), pod_uid.end(), '_', '-');
    }

    // retrieve thread entry associated with the event tid
    auto& tr = in.get_table_reader();
    auto thread_entry = m_thread_table.get_entry(
            tr, (int64_t)in.get_event_reader().get_tid());

    // Write the pod_uid into the entry
    auto& tw = in.get_table_writer();
    m_pod_uid_field.write_value(tw, thread_entry, (const char*)pod_uid.c_str());
    return true;
}

bool my_plugin::parse_event(const falcosecurity::parse_event_input& in)
{
    // NOTE: today in the libs framework, parsing errors are not logged
    auto& evt = in.get_event_reader();

    switch(evt.get_type())
    {
    case PPME_ASYNCEVENT_E:
        return parse_async_event(in);
    case PPME_SYSCALL_EXECVE_19_X:
    case PPME_SYSCALL_EXECVEAT_X:
    case PPME_SYSCALL_CLONE_20_X:
    case PPME_SYSCALL_FORK_20_X:
    case PPME_SYSCALL_VFORK_20_X:
    case PPME_SYSCALL_CLONE3_X:
        return extract_pod_uid(in);
    default:
        SPDLOG_ERROR("received an unknown event type {}",
                     int32_t(evt.get_type()));
        return false;
    }
}
