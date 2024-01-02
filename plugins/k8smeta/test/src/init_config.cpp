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

TEST_F(sinsp_with_test_input, plugin_k8s_empty_init_config)
{
    auto plugin_owner = m_inspector.register_plugin(PLUGIN_PATH);
    ASSERT_TRUE(plugin_owner.get());
    std::string err;

    // The plugin requires an init config with a precise schema
    ASSERT_THROW(plugin_owner->init("", err), sinsp_exception);
}

TEST_F(sinsp_with_test_input, plugin_k8s_init_with_missing_required_argument)
{
    auto plugin_owner = m_inspector.register_plugin(PLUGIN_PATH);
    ASSERT_TRUE(plugin_owner.get());
    std::string err;

    // The node name is also a required argument, but here it is not provided
    ASSERT_THROW(plugin_owner->init("{\"collectorHostname\":\"localhost\","
                                    "\"collectorPort\":\"45000\"}",
                                    err),
                 sinsp_exception);
}

TEST_F(sinsp_with_test_input, plugin_k8s_init_with_not_allowed_verbosity_value)
{
    auto plugin_owner = m_inspector.register_plugin(PLUGIN_PATH);
    ASSERT_TRUE(plugin_owner.get());
    std::string err;

    // `warn` is not a valid value for the `verbosity` field
    ASSERT_THROW(plugin_owner->init("{\"collectorHostname\":\"localhost\","
                                    "\"collectorPort\":\"45000\",\"nodeName\":"
                                    "\"control-plane\",\"verbosity\":\"warn\"}",
                                    err),
                 sinsp_exception);
}

TEST_F(sinsp_with_test_input, plugin_k8s_with_simple_config)
{
    auto plugin_owner = m_inspector.register_plugin(PLUGIN_PATH);
    ASSERT_TRUE(plugin_owner.get());
    std::string err;

    ASSERT_NO_THROW(plugin_owner->init(R"(
{"collectorHostname":"localhost","collectorPort":45000,"nodeName":"kind-control-plane"})",
                                       err));
    ASSERT_EQ(err, "");
}

TEST_F(sinsp_with_test_input, plugin_k8s_env_variable)
{
    auto plugin_owner = m_inspector.register_plugin(PLUGIN_PATH);
    ASSERT_TRUE(plugin_owner.get());
    std::string err;

    std::string env_var_name = "FALCO_NODE_NAME";
    std::string env_var_value = "kind_control_plane";

    setenv(env_var_name.c_str(), env_var_value.c_str(), 1);

    ASSERT_NO_THROW(plugin_owner->init(R"(
{"collectorHostname":"localhost","collectorPort":45000,"nodeName":" ${FALCO_NODE_NAME} "})",
                                       err));
    ASSERT_EQ(err, "");
}
