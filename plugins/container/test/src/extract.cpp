/*
Copyright (C) 2025 The Falco Authors.

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

#include <string>

#include <gtest/gtest.h>
#include <helpers/threads_helpers.h>

#include <container_tests/plugin_test_var.h>

// Minimal init config for testing (no container engines enabled)
static const std::string INIT_CONFIG_STR = R"({
    "engines": {
        "docker": {
            "enabled": false,
            "sockets": []
        },
        "containerd": {
            "enabled": false,
            "sockets": []
        },
        "cri": {
            "enabled": false,
            "sockets": []
        },
        "podman": {
            "enabled": false,
            "sockets": []
        },
        "bpm": {
            "enabled": false
        },
        "lxc": {
            "enabled": false
        },
        "libvirt_lxc": {
            "enabled": false
        }
    }
})";

// Config with docker enabled for cgroup matching tests
// Note: empty sockets array means no listener, but cgroup matching still works
static const std::string INIT_CONFIG_DOCKER_ENABLED_STR = R"({
    "engines": {
        "docker": {
            "enabled": true,
            "sockets": []
        },
        "containerd": {
            "enabled": false,
            "sockets": []
        },
        "cri": {
            "enabled": false,
            "sockets": []
        },
        "podman": {
            "enabled": false,
            "sockets": []
        },
        "bpm": {
            "enabled": false
        },
        "lxc": {
            "enabled": false
        },
        "libvirt_lxc": {
            "enabled": false
        }
    }
})";

static inline std::shared_ptr<sinsp_plugin>
assert_plugin_initialization(sinsp& inspector, filter_check_list& pl_flist)
{
    auto plugin_owner = inspector.register_plugin(PLUGIN_PATH);
    EXPECT_TRUE(plugin_owner.get());
    std::string err;
    EXPECT_TRUE(plugin_owner->init(INIT_CONFIG_STR, err)) << "err: " << err;
    pl_flist.add_filter_check(inspector.new_generic_filtercheck());
    pl_flist.add_filter_check(sinsp_plugin::new_filtercheck(plugin_owner));
    return plugin_owner;
}

static inline std::shared_ptr<sinsp_plugin>
assert_plugin_initialization_with_config(sinsp& inspector,
                                         filter_check_list& pl_flist,
                                         const std::string& config)
{
    auto plugin_owner = inspector.register_plugin(PLUGIN_PATH);
    EXPECT_TRUE(plugin_owner.get());
    std::string err;
    EXPECT_TRUE(plugin_owner->init(config, err)) << "err: " << err;
    pl_flist.add_filter_check(inspector.new_generic_filtercheck());
    pl_flist.add_filter_check(sinsp_plugin::new_filtercheck(plugin_owner));
    return plugin_owner;
}

TEST_F(sinsp_with_test_input, plugin_container_basic_API)
{
    filter_check_list pl_flist;
    auto plugin_owner = assert_plugin_initialization(m_inspector, pl_flist);

    ASSERT_EQ(plugin_owner->caps(),
              CAP_EXTRACTION | CAP_PARSING | CAP_ASYNC | CAP_CAPTURE_LISTENING);
    ASSERT_EQ(plugin_owner->name(), "container");
    ASSERT_EQ(plugin_owner->description(),
              "Falco container metadata enrichment Plugin");
}

TEST_F(sinsp_with_test_input, plugin_container_extract_container_id_field)
{
    filter_check_list pl_flist;
    auto plugin_owner = assert_plugin_initialization(m_inspector, pl_flist);

    add_default_init_thread();
    open_inspector();

    sinsp_evt* evt;
    evt = generate_execve_enter_and_exit_event(0, INIT_TID, INIT_TID, INIT_PID,
                                               INIT_PTID, "init", "init",
                                               "/lib/systemd/systemd", {});

    ASSERT_NE(evt, nullptr);
    ASSERT_EQ(evt->get_type(), PPME_SYSCALL_EXECVE_19_X);

    ASSERT_TRUE(field_exists(evt, "container.id", pl_flist));

    std::string container_id =
            get_field_as_string(evt, "container.id", pl_flist);
    ASSERT_TRUE(container_id == "host" || container_id.empty());
}

TEST_F(sinsp_with_test_input, plugin_container_extract_container_name_field)
{
    filter_check_list pl_flist;
    auto plugin_owner = assert_plugin_initialization(m_inspector, pl_flist);

    add_default_init_thread();
    open_inspector();

    sinsp_evt* evt;
    evt = generate_execve_enter_and_exit_event(0, INIT_TID, INIT_TID, INIT_PID,
                                               INIT_PTID, "init", "init",
                                               "/lib/systemd/systemd", {});

    ASSERT_NE(evt, nullptr);

    // Check that container.name field exists
    ASSERT_TRUE(field_exists(evt, "container.name", pl_flist));
}

// Container JSON for async event injection
// The full_id must be exactly 64 hex characters for docker cgroup matching
static const char* TEST_CONTAINER_JSON = R"({
    "container": {
        "type": 0,
        "id": "abc123def456",
        "full_id": "abc123def4567890123456789012345678901234567890123456789012345678",
        "name": "test-nginx-container",
        "image": "nginx:1.25-alpine",
        "imageid": "sha256:a8758716bb6aa4d90071160d27028fe4eaee7ce8166221a97d30440c8eac2be6",
        "imagerepo": "nginx",
        "imagetag": "1.25-alpine",
        "imagedigest": "sha256:a8758716bb6a",
        "privileged": true,
        "labels": {
            "app": "webserver",
            "env": "testing",
            "version": "1.0"
        },
        "ip": "172.17.0.5",
        "created_time": 1700000000,
        "Mounts": [],
        "env": [],
        "port_mappings": [],
        "memory_limit": 536870912,
        "cpu_shares": 1024,
        "cpu_quota": 0,
        "cpu_period": 100000
    }
})";

static const std::string TEST_CONTAINER_FULL_ID =
        "abc123def4567890123456789012345678901234567890123456789012345678";

TEST_F(sinsp_with_test_input,
       plugin_container_extract_with_async_container_event)
{
    filter_check_list pl_flist;
    auto plugin_owner = assert_plugin_initialization_with_config(
            m_inspector, pl_flist, INIT_CONFIG_DOCKER_ENABLED_STR);

    add_default_init_thread();
    open_inspector();

    uint64_t ts = increasing_ts();
    scap_const_sized_buffer json_buf = {TEST_CONTAINER_JSON,
                                        strlen(TEST_CONTAINER_JSON) + 1};
    add_async_event(ts, INIT_TID, PPME_ASYNCEVENT_E, 3,
                    (uint32_t)0, // plugin_id
                    "container", // async event name
                    json_buf);   // JSON data

    sinsp_evt* async_evt = advance_ts_get_event(ts);
    ASSERT_NE(async_evt, nullptr);
    ASSERT_EQ(async_evt->get_type(), PPME_ASYNCEVENT_E);

    std::vector<std::string> docker_cgroups = {
            "cpuset=/docker/" + TEST_CONTAINER_FULL_ID,
            "cpu=/docker/" + TEST_CONTAINER_FULL_ID,
            "memory=/docker/" + TEST_CONTAINER_FULL_ID};

    sinsp_evt* evt = generate_execve_enter_and_exit_event(
            0,        // retval (success)
            100,      // old_tid
            100,      // new_tid
            100,      // pid
            INIT_TID, // ppid
            "/usr/sbin/nginx", "nginx", "/usr/sbin/nginx", docker_cgroups);

    ASSERT_NE(evt, nullptr);
    ASSERT_EQ(evt->get_type(), PPME_SYSCALL_EXECVE_19_X);

    std::string container_id =
            get_field_as_string(evt, "container.id", pl_flist);
    ASSERT_EQ(container_id, "abc123def456");

    std::string container_name =
            get_field_as_string(evt, "container.name", pl_flist);
    ASSERT_EQ(container_name, "test-nginx-container");

    std::string container_image =
            get_field_as_string(evt, "container.image", pl_flist);
    ASSERT_EQ(container_image, "nginx:1.25-alpine");

    std::string container_image_repo =
            get_field_as_string(evt, "container.image.repository", pl_flist);
    ASSERT_EQ(container_image_repo, "nginx");

    std::string container_image_tag =
            get_field_as_string(evt, "container.image.tag", pl_flist);
    ASSERT_EQ(container_image_tag, "1.25-alpine");

    std::string container_type =
            get_field_as_string(evt, "container.type", pl_flist);
    ASSERT_EQ(container_type, "docker");

    std::string privileged =
            get_field_as_string(evt, "container.privileged", pl_flist);
    ASSERT_EQ(privileged, "true");

    std::string container_ip =
            get_field_as_string(evt, "container.ip", pl_flist);
    ASSERT_EQ(container_ip, "172.17.0.5");

    std::string app_label =
            get_field_as_string(evt, "container.label[app]", pl_flist);
    ASSERT_EQ(app_label, "webserver");

    std::string env_label =
            get_field_as_string(evt, "container.label[env]", pl_flist);
    ASSERT_EQ(env_label, "testing");
}

TEST_F(sinsp_with_test_input, plugin_container_extract_multiple_containers)
{
    filter_check_list pl_flist;
    auto plugin_owner = assert_plugin_initialization_with_config(
            m_inspector, pl_flist, INIT_CONFIG_DOCKER_ENABLED_STR);

    add_default_init_thread();
    open_inspector();

    // Container 1: nginx (full_id must be exactly 64 hex chars)
    static const char* CONTAINER1_JSON = R"({
        "container": {
            "type": 0,
            "id": "aaaaaaaaaaaa",
            "full_id": "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeee1234",
            "name": "web-frontend",
            "image": "nginx:latest",
            "imagerepo": "nginx",
            "imagetag": "latest",
            "privileged": false,
            "labels": {"role": "frontend"},
            "ip": "172.17.0.10"
        }
    })";

    // Container 2: redis (full_id must be exactly 64 hex chars)
    static const char* CONTAINER2_JSON = R"({
        "container": {
            "type": 0,
            "id": "111111111111",
            "full_id": "1111111111112222222222223333333333334444444444445555555555556666",
            "name": "cache-backend",
            "image": "redis:7-alpine",
            "imagerepo": "redis",
            "imagetag": "7-alpine",
            "privileged": false,
            "labels": {"role": "cache"},
            "ip": "172.17.0.11"
        }
    })";

    // Inject both containers
    uint64_t ts1 = increasing_ts();
    scap_const_sized_buffer json1 = {CONTAINER1_JSON,
                                     strlen(CONTAINER1_JSON) + 1};
    add_async_event(ts1, INIT_TID, PPME_ASYNCEVENT_E, 3, (uint32_t)0,
                    "container", json1);
    advance_ts_get_event(ts1);

    uint64_t ts2 = increasing_ts();
    scap_const_sized_buffer json2 = {CONTAINER2_JSON,
                                     strlen(CONTAINER2_JSON) + 1};
    add_async_event(ts2, INIT_TID, PPME_ASYNCEVENT_E, 3, (uint32_t)0,
                    "container", json2);
    advance_ts_get_event(ts2);

    // Process in container 1 (cgroup must have exactly 64 hex char container
    // ID)
    std::vector<std::string> cgroups1 = {
            "cpu=/docker/"
            "aaaaaaaaaaaabbbbbbbbbbbbccccccccccccddddddddddddeeeeeeeeeeee1234"};
    sinsp_evt* evt1 = generate_execve_enter_and_exit_event(
            0, 200, 200, 200, INIT_TID, "/usr/sbin/nginx", "nginx",
            "/usr/sbin/nginx", cgroups1);
    ASSERT_NE(evt1, nullptr);

    ASSERT_EQ(get_field_as_string(evt1, "container.id", pl_flist),
              "aaaaaaaaaaaa");
    ASSERT_EQ(get_field_as_string(evt1, "container.name", pl_flist),
              "web-frontend");
    ASSERT_EQ(get_field_as_string(evt1, "container.label[role]", pl_flist),
              "frontend");

    // Process in container 2 (cgroup must have exactly 64 hex char container
    // ID)
    std::vector<std::string> cgroups2 = {
            "cpu=/docker/"
            "1111111111112222222222223333333333334444444444445555555555556666"};
    sinsp_evt* evt2 = generate_execve_enter_and_exit_event(
            0, 300, 300, 300, INIT_TID, "/usr/bin/redis-server", "redis-server",
            "/usr/bin/redis-server", cgroups2);
    ASSERT_NE(evt2, nullptr);

    ASSERT_EQ(get_field_as_string(evt2, "container.id", pl_flist),
              "111111111111");
    ASSERT_EQ(get_field_as_string(evt2, "container.name", pl_flist),
              "cache-backend");
    ASSERT_EQ(get_field_as_string(evt2, "container.label[role]", pl_flist),
              "cache");
}

// This is a regression test for
// https://github.com/falcosecurity/plugins/issues/1076 (fixed in PR #1112)
TEST_F(sinsp_with_test_input, plugin_container_extract_on_async_event)
{
    filter_check_list pl_flist;
    auto plugin_owner = assert_plugin_initialization(m_inspector, pl_flist);

    add_default_init_thread();
    open_inspector();

    // Create a container async event
    scap_const_sized_buffer json_buf = {TEST_CONTAINER_JSON,
                                        strlen(TEST_CONTAINER_JSON) + 1};
    uint64_t ts = increasing_ts();
    add_async_event(ts, INIT_TID, PPME_ASYNCEVENT_E, 3, (uint32_t)0,
                    "container", json_buf);

    sinsp_evt* async_evt = next_event();
    ASSERT_NE(async_evt, nullptr);
    ASSERT_EQ(async_evt->get_type(), PPME_ASYNCEVENT_E);

    // Before the fix (PR #1112), accessing these fields would crash because
    // they try to read from the uninitialized thread_entry.
    ASSERT_EQ(get_field_as_string(async_evt, "container.id", pl_flist),
              "abc123def456");
    ASSERT_EQ(get_field_as_string(async_evt, "container.name", pl_flist),
              "test-nginx-container");

    // Fields that read from thread_entry (pidns_init_start_ts):
    (void)field_has_value(async_evt, "container.duration", pl_flist);
    (void)field_has_value(async_evt, "container.start_ts", pl_flist);

    (void)field_has_value(async_evt, "proc.is_container_healthcheck", pl_flist);
    (void)field_has_value(async_evt, "proc.is_container_liveness_probe",
                          pl_flist);
    (void)field_has_value(async_evt, "proc.is_container_readiness_probe",
                          pl_flist);
}
