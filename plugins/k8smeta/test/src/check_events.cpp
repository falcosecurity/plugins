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

#include <gtest/gtest.h>
#include <plugin.h>
#include <test/helpers/threads_helpers.h>
#include <exception>
#include <fstream>

// Obtained from the plugin folder
#include <k8smeta_tests/json.hpp>
#include <k8smeta_tests/plugin_test_var.h>
#include <k8smeta_tests/shared_with_tests_consts.h>
#include <k8smeta_tests/helpers.h>

class k8s_json_extractor
{
    public:
    k8s_json_extractor()
    {
        std::ifstream json_file(JSON_TEST_FILE_PATH);

        if(!json_file.is_open())
        {
            throw std::runtime_error("unable to open the json file: " +
                                     std::string(JSON_TEST_FILE_PATH));
        }

        nlohmann::json parsed_json_file;
        json_file >> parsed_json_file;

        m_num_events = 0;
        for(auto& elem : parsed_json_file)
        {
            m_num_events++;
            m_json_events.push_back(elem);
        }
    }

    uint32_t get_num_events() const { return m_num_events; }

    bool compare_json_event(uint32_t evt_idx,
                            nlohmann::json json_to_compare) const
    {
        if(m_json_events.size() < evt_idx)
        {
            throw std::runtime_error("There are not enough events in the json "
                                     "file! Event in the json file: '" +
                                     std::to_string(get_num_events()) +
                                     "', index required: '" +
                                     std::to_string(evt_idx) + "'");
        }
        return m_json_events[evt_idx] == json_to_compare;
    }

    nlohmann::json get_json_event(uint32_t evt_idx) const
    {
        if(m_json_events.size() < evt_idx)
        {
            throw std::runtime_error("There are not enough events in the json "
                                     "file! Event in the json file: '" +
                                     std::to_string(get_num_events()) +
                                     "', index required: '" +
                                     std::to_string(evt_idx) + "'");
        }
        return m_json_events[evt_idx];
    }

    bool match_json_event(std::string reason, std::string resource_uid,
                          nlohmann::json event_json)
    {
        std::string event_uid;
        std::string event_reason;

        if(!event_json.contains(nlohmann::json::json_pointer(UID_PATH)) ||
           !event_json.contains(nlohmann::json::json_pointer(REASON_PATH)))
        {
            return false;
        }

        event_json.at(nlohmann::json::json_pointer(REASON_PATH))
                .get_to(event_reason);
        event_json.at(nlohmann::json::json_pointer(UID_PATH)).get_to(event_uid);

        return (event_uid.compare(resource_uid) == 0) &&
               (event_reason.compare(reason) == 0);
    }

    nlohmann::json find_json_resource(std::string resource_uid,
                                      int64_t max_num_event = 0)
    {
        // If not specified we search until the last event
        if(max_num_event == 0)
        {
            max_num_event = m_num_events;
        }

        nlohmann::json target_resource_json;
        for(uint32_t i = 0; i < m_num_events; i++)
        {
            if(match_json_event(REASON_CREATE, resource_uid,
                                m_json_events[i]) ||
               match_json_event(REASON_UPDATE, resource_uid, m_json_events[i]))
            {
                target_resource_json = m_json_events[i];
            }

            if(match_json_event(REASON_DELETE, resource_uid, m_json_events[i]))
            {
                target_resource_json = "";
            }
        }

        if(target_resource_json == "")
        {
            throw std::runtime_error("Resource with uid '" + resource_uid +
                                     "' not found after " +
                                     std::to_string(max_num_event) +
                                     " events.");
        }
        return target_resource_json;
    }

    void read_all_events(sinsp& m_inspector)
    {
        int rc = 0;
        uint32_t num_async_events = 0;
        sinsp_evt* evt = NULL;

        // We should always receive all the events from the plugin because
        // otherwise we don't know how many events we be processed at max in the
        // main loop, all depends on the async thread.
        while(this->get_num_events() != num_async_events)
        {
            rc = m_inspector.next(&evt);
            if(rc == SCAP_SUCCESS && evt != nullptr &&
               evt->get_type() == PPME_ASYNCEVENT_E)
            {
                num_async_events++;
            }
        }
    }

    // K8S_POD_NAME
    std::string extract_pod_name(std::string pod_uid, int64_t max_num_event = 0)
    {
        auto pod_json = find_json_resource(pod_uid, max_num_event);

        std::string meta_string;
        pod_json.at(nlohmann::json::json_pointer(META_PATH))
                .get_to(meta_string);
        nlohmann::json meta_json = nlohmann::json::parse(meta_string);

        std::string pod_name;
        meta_json.at(nlohmann::json::json_pointer(NAME_PATH)).get_to(pod_name);
        return pod_name;
    }

    private:
    std::vector<nlohmann::json> m_json_events;
    uint32_t m_num_events;
};

// Check plugin basic APIs
TEST_F(sinsp_with_test_input, plugin_k8s_basic_API)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    ASSERT_EQ(plugin_owner->caps(), CAP_EXTRACTION | CAP_PARSING | CAP_ASYNC);
    ASSERT_EQ(plugin_owner->name(), PLUGIN_NAME);
    ASSERT_EQ(plugin_owner->description(), PLUGIN_DESCRIPTION);
    ASSERT_EQ(plugin_owner->contact(), PLUGIN_CONTACT);
    ASSERT_EQ(plugin_owner->plugin_version(), sinsp_version(PLUGIN_VERSION));
    // The framework version should be compatible with the version required by
    // the plugin
    ASSERT_TRUE(sinsp_version(PLUGIN_API_VERSION_STR)
                        .compatible_with(plugin_owner->required_api_version()));
    ASSERT_STRING_SETS(plugin_owner->async_event_names(), ASYNC_EVENT_NAMES);
    ASSERT_STRING_SETS(plugin_owner->async_event_sources(),
                       ASYNC_EVENT_SOURCES);

    // We want to extract all syscall events
    ASSERT_PPME_SETS(plugin_owner->extract_event_codes(),
                     libsinsp::events::all_event_set());
    ASSERT_STRING_SETS(plugin_owner->extract_event_sources(),
                       EXTRACT_EVENT_SOURCES);

    auto parse_event_codes = libsinsp::events::set<ppm_event_code>{
            PPME_ASYNCEVENT_E,       PPME_SYSCALL_EXECVE_19_X,
            PPME_SYSCALL_EXECVEAT_X, PPME_SYSCALL_CLONE_20_X,
            PPME_SYSCALL_FORK_20_X,  PPME_SYSCALL_VFORK_20_X,
            PPME_SYSCALL_CLONE3_X};
    ASSERT_PPME_SETS(plugin_owner->parse_event_codes(), parse_event_codes);
    ASSERT_STRING_SETS(plugin_owner->parse_event_sources(),
                       PARSE_EVENT_SOURCES);

    // The plugin provide a json schema
    ss_plugin_schema_type schema_type;
    plugin_owner->get_init_schema(schema_type);
    ASSERT_EQ(schema_type, SS_PLUGIN_SCHEMA_JSON);
}

// Check all plugin fields
TEST_F(sinsp_with_test_input, plugin_k8s_fields_existance)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();
    open_inspector();

    // Obtain an event to assert the filterchecks presence against it.
    auto evt = generate_random_event(INIT_TID);
    ASSERT_TRUE(field_exists(evt, "k8smeta.pod.name", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.pod.uid", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.pod.label[exists]", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.pod.labels", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.pod.ip", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.ns.name", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.ns.uid", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.ns.label[exists]", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.ns.labels", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.deployment.name", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.deployment.uid", pl_flist));
    ASSERT_TRUE(
            field_exists(evt, "k8smeta.deployment.label[exists]", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.deployment.labels", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.svc.name", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.svc.uid", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.svc.label[exists]", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.svc.labels", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.rs.name", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.rs.uid", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.rs.label[exists]", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.rs.labels", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.name", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.uid", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.label[exists]", pl_flist));
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.labels", pl_flist));

    // The label field must always have an argument with `[]` notation
    ASSERT_THROW(field_exists(evt, "k8smeta.pod.label.notexists", pl_flist),
                 sinsp_exception);
    ASSERT_THROW(field_exists(evt, "k8smeta.ns.labelnotexists", pl_flist),
                 sinsp_exception);
}

// Check that the plugin can send all the events received from the server
// without altering them. Assert the number and the json content.
TEST_F(sinsp_with_test_input, plugin_k8s_content_of_async_events)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    open_inspector();

    sinsp_evt* evt = NULL;

    int rc = 0;
    uint32_t num_async_events = 0;
    k8s_json_extractor extractor;
    while(extractor.get_num_events() != num_async_events)
    {
        rc = m_inspector.next(&evt);
        if(rc == SCAP_SUCCESS && evt != nullptr &&
           evt->get_type() == PPME_ASYNCEVENT_E)
        {
            ASSERT_EQ(evt->get_tid(), -1);
            ASSERT_EQ(evt->get_source_idx(), 0);
            ASSERT_EQ(std::string(evt->get_source_name()), "syscall");
            ASSERT_STREQ(evt->get_param(1)->m_val, "k8s");

            // Check that the content of the event is right
            // We need to compare the json because the dumped strings could be
            // out of order
            ASSERT_EQ(extractor.get_json_event(num_async_events),
                      nlohmann::json::parse(evt->get_param(2)->m_val));
            num_async_events++;
        }
    }
    ASSERT_EQ(extractor.get_num_events(), num_async_events);
}

// Check pod filterchecks value
TEST_F(sinsp_with_test_input, plugin_k8s_pod_refs)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    // Open test inspector
    add_default_init_thread();
    open_inspector();

    k8s_json_extractor extractor;
    extractor.read_all_events(m_inspector);

    // Call an execve event on init to set the pod uid.
    sinsp_evt* evt = NULL;
    std::string pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
    GENERATE_EXECVE_EVENT_FOR_INIT(pod_uid);

    // K8S_POD_NAME
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.name", pl_flist),
              "metrics-server-85d6fcf458-tqkcv");

    // K8S_POD_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.uid", pl_flist), pod_uid);

    // K8S_POD_LABEL
    ASSERT_TRUE(field_exists(evt, "k8smeta.pod.label[no]", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.label[k8s-app]", pl_flist),
              "metrics-server");

    // K8S_POD_LABELS
    ASSERT_TRUE(field_exists(evt, "k8smeta.pod.labels", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.labels", pl_flist),
              "(pod-template-hash:85d6fcf458,k8s-app:metrics-server)");

    // K8S_POD_IP
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.ip", pl_flist),
              "10.16.1.2");

    // K8S_NS_NAME
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.ns.name", pl_flist),
              "kube-system");

    // K8S_NS_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.ns.uid", pl_flist),
              "c51d0620-b1e1-449a-a6f2-9f96830831a9");

    // K8S_NS_LABEL
    ASSERT_TRUE(field_exists(evt, "k8smeta.ns.label[no]", pl_flist));
    ASSERT_EQ(get_field_as_string(
                      evt, "k8smeta.ns.label[kubernetes.io/metadata.name]",
                      pl_flist),
              "kube-system");

    // K8S_NS_LABELS
    ASSERT_TRUE(field_exists(evt, "k8smeta.ns.labels", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.ns.labels", pl_flist),
              "(kubernetes.io/metadata.name:kube-system)");

    // K8S_DEPLOYMENT_NAME
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.deployment.name", pl_flist),
              "metrics-server");

    // K8S_DEPLOYMENT_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.deployment.uid", pl_flist),
              "e56cf37d-5b8b-4b2d-b7bc-3316a3d72e93");

    // K8S_DEPLOYMENT_LABEL
    ASSERT_TRUE(field_exists(evt, "k8smeta.deployment.label[no]", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.deployment.label[k8s-app]",
                                  pl_flist),
              "metrics-server");

    // K8S_DEPLOYMENT_LABELS
    ASSERT_TRUE(field_exists(evt, "k8smeta.deployment.labels", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.deployment.labels", pl_flist),
              "(k8s-app:metrics-server)");

    // K8S_SVC_NAME
    // This field is a list so we have this `( )` notation
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.name", pl_flist),
              "(metrics-server)");

    // K8S_SVC_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.uid", pl_flist),
              "(b2af0913-1a07-457f-986a-111caa4fb372)");

    // K8S_SVC_LABEL
    ASSERT_TRUE(field_exists(evt, "k8smeta.svc.label[no]", pl_flist));
    // This field is a list so we have this `( )` notation
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.label[k8s-app]", pl_flist),
              "(metrics-server)");

    // K8S_SVC_LABELS
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.labels", pl_flist),
              "(k8s-app:metrics-server)");

    // K8S_RS_NAME
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.rs.name", pl_flist),
              "metrics-server-85d6fcf458");

    // K8S_RS_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.rs.uid", pl_flist),
              "8be7cb9d-f96a-41b5-8fb0-81fda92a663a");

    // K8S_RS_LABEL
    ASSERT_TRUE(field_exists(evt, "k8smeta.rs.label[no]", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.rs.label[pod-template-hash]",
                                  pl_flist),
              "85d6fcf458");

    // K8S_RS_LABELS
    ASSERT_TRUE(field_exists(evt, "k8smeta.rs.labels", pl_flist));
    // This field is a list so we have this `( )` notation
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.rs.labels", pl_flist),
              "(pod-template-hash:85d6fcf458,k8s-app:metrics-server)");

    // K8S_RC_NAME
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.name", pl_flist));

    // K8S_RC_UID
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.uid", pl_flist));

    // K8S_RC_LABEL
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.label[no]", pl_flist));

    // K8S_RC_LABELS
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.labels", pl_flist));

    m_inspector.close();
}

// Check pod with 2 services
TEST_F(sinsp_with_test_input, plugin_k8s_pod_with_2_services)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    // Open test inspector
    add_default_init_thread();
    open_inspector();

    k8s_json_extractor extractor;
    extractor.read_all_events(m_inspector);

    // From now on we have the pod and the 2 corresponding services are already
    // parsed
    sinsp_evt* evt = NULL;
    std::string pod_uid = "0cc53e7d-1d9f-4798-926b-451364a4ec8e";
    GENERATE_EXECVE_EVENT_FOR_INIT(pod_uid);

    // K8S_POD_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.uid", pl_flist), pod_uid);

    // K8S_SVC_NAME
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.name", pl_flist),
              "(nginx-service,nginx-service-second-service)");

    // K8S_SVC_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.uid", pl_flist),
              "(f0fea0cd-24cd-439f-bd51-e7a9100fed40,9e840fbe-93e4-412c-aa23-"
              "fbe6d03efd08)");

    // K8S_SVC_LABEL
    ASSERT_TRUE(field_exists(evt, "k8smeta.svc.label[no]", pl_flist));
    // Both services have the `app` label
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.label[app]", pl_flist),
              "(custom,custom-2)");
    // Only one of the 2 services has the value for the label
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.label[service]", pl_flist),
              "(service1)");

    // K8S_SVC_LABELS
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.labels", pl_flist),
              "(service:service1,app:custom,app:custom-2)");

    m_inspector.close();
}

// Check replicationController fields
TEST_F(sinsp_with_test_input, plugin_k8s_pod_with_repliacation_controller)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    // Open test inspector
    add_default_init_thread();
    open_inspector();

    k8s_json_extractor extractor;
    extractor.read_all_events(m_inspector);

    // From now on we have the pod and the corresponding replicationController
    sinsp_evt* evt = NULL;
    std::string pod_uid = "00e704ac-77d1-4aac-80af-31233b277889";
    GENERATE_EXECVE_EVENT_FOR_INIT(pod_uid);

    // K8S_POD_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.uid", pl_flist), pod_uid);

    // K8S_RC_NAME
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.rc.name", pl_flist), "nginx");

    // K8S_RC_UID
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.rc.uid", pl_flist),
              "f2e2a261-ba86-4fa6-9493-e5260a106126");

    // K8S_RC_LABEL
    ASSERT_TRUE(field_exists(evt, "k8smeta.rc.label[no]", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.rc.label[app]", pl_flist),
              "nginx");

    // K8S_RC_LABELS
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.rc.labels", pl_flist),
              "(app:nginx)");

    m_inspector.close();
}

// Remove namespace and deployment associated with the pod and check 2 things:
// 1. the plugin doesn't crash
// 2. the pod fields are still accessible but the deployment and namespace ones
// no
TEST_F(sinsp_with_test_input, plugin_k8s_delete_namespace_and_deployment)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    // Open test inspector
    add_default_init_thread();
    open_inspector();

    k8s_json_extractor extractor;
    extractor.read_all_events(m_inspector);

    sinsp_evt* evt = NULL;
    std::string pod_uid = "0cc53e7d-1d9f-4798-926b-451364a4fgjs";
    GENERATE_EXECVE_EVENT_FOR_INIT(pod_uid);

    // In the test file we added:
    // - a Pod with uid `0cc53e7d-1d9f-4798-926b-451364a4fgjs`
    // - a Namespace with uid `f7ju8b13-df0c-43bd-8ded-973f4ede66c6`
    // - a Deployment with uid `920r1601-61b6-4d46-8916-db9f36414722`
    //
    // The Namespace and Depleyoment are removed so we shouldn't be able to
    // extract their fields

    // The pod should be still here
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.uid", pl_flist), pod_uid);

    // The namespace name is extracted from the pod meta so we still have it
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.ns.name", pl_flist), "default");
    // The namespace uid is available because it is obtained from the pod refs
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.ns.uid", pl_flist),
              "f7ju8b13-df0c-43bd-8ded-973f4ede66c6");
    // The deployment uid is available because it is obtained from the pod refs
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.deployment.uid", pl_flist),
              "920r1601-61b6-4d46-8916-db9f36414722");

    // These resources are removed so we shouldn't have fields
    ASSERT_FALSE(field_has_value(
            evt, "k8smeta.ns.label[kubernetes.io/metadata.name]", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.ns.labels", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.deployment.name", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.deployment.label[k8s-app]",
                                 pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.deployment.labels", pl_flist));

    m_inspector.close();
}

// Delete a pod, all associated resources should be no more available from this
// pod, but they should be available from other pods
TEST_F(sinsp_with_test_input, plugin_k8s_delete_a_pod)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    // Open test inspector
    add_default_init_thread();
    open_inspector();

    k8s_json_extractor extractor;
    extractor.read_all_events(m_inspector);

    // This Pod is deleted, all fields should be NULL
    sinsp_evt* evt = NULL;
    std::string pod_uid = "0cc0927d-1d9f-4798-926b-451364a4fgjs";
    GENERATE_EXECVE_EVENT_FOR_INIT(pod_uid);

    ASSERT_FALSE(field_has_value(evt, "k8smeta.pod.name", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.pod.uid", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.pod.label[exists]", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.pod.labels", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.pod.ip", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.ns.name", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.ns.uid", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.ns.label[exists]", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.ns.labels", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.deployment.name", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.deployment.uid", pl_flist));
    ASSERT_FALSE(
            field_has_value(evt, "k8smeta.deployment.label[exists]", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.deployment.labels", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.svc.name", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.svc.uid", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.svc.label[exists]", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.svc.labels", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.rs.name", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.rs.uid", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.rs.label[exists]", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.rs.labels", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.rc.name", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.rc.uid", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.rc.label[exists]", pl_flist));
    ASSERT_FALSE(field_has_value(evt, "k8smeta.rc.labels", pl_flist));

    // Now we use a pod that still exists and is associated with the same
    // Namespace and Deployment We want to check that the Namespace and the
    // Deployment are still there.
    pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
    GENERATE_EXECVE_EVENT_FOR_INIT(pod_uid);

    ASSERT_TRUE(field_has_value(evt, "k8smeta.pod.name", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.pod.uid", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.pod.labels", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.pod.ip", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.ns.name", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.ns.uid", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.ns.labels", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.deployment.name", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.deployment.uid", pl_flist));
    ASSERT_TRUE(field_has_value(evt, "k8smeta.deployment.labels", pl_flist));

    m_inspector.close();
}

// Check that after an "Update" event the plugin tables are updated
// We check 2 updates on 2 different pods
TEST_F(sinsp_with_test_input, plugin_k8s_update_a_pod)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    // Open test inspector
    add_default_init_thread();
    open_inspector();

    k8s_json_extractor extractor;
    extractor.read_all_events(m_inspector);

    sinsp_evt* evt = NULL;
    std::string pod_uid = "1d34c7bb-7d94-4f00-bed9-fe4eca61d446";
    GENERATE_EXECVE_EVENT_FOR_INIT(pod_uid);

    // After 2 "Updated" events the pod has 2 services
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.svc.uid", pl_flist),
              "(f0fea0cd-24cd-439f-bd51-e7a9100fed40,9e840fbe-93e4-412c-aa23-"
              "fbe6d03efd08)");

    // Check another pod that after an "Updated" event has a pod ip
    pod_uid = "e581fe16-cde8-4075-a159-cd8ddd5b8fbc";
    GENERATE_EXECVE_EVENT_FOR_INIT(pod_uid);

    // After 2 "Updated" events the pod has 2 services
    ASSERT_EQ(get_field_as_string(evt, "k8smeta.pod.ip", pl_flist),
              "10.16.1.20");
    m_inspector.close();
}

////////////////////////////////////
// Missing tests
//////////////////////////////////

/// todo! Add some tests

// add a test on a resource without the `/labels` key.

// Check on a scap file

// Read a scap-file/huge json file and evaluate perf
