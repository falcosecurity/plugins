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
#include <test/helpers/threads_helpers.h>
#include <re2/re2.h>

// Obtained from the plugin folder
#include <k8smeta_tests/plugin_test_var.h>
#include <k8smeta_tests/shared_with_tests_consts.h>
#include <k8smeta_tests/helpers.h>

// All tests regarding the pod parsing logic and addition/removal of the pod
// field to the thread table.

// Check pod regex with different formats
TEST_F(sinsp_with_test_input, plugin_k8s_pod_uid_regex)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();
    open_inspector();

    auto &reg = m_inspector.get_table_registry();
    auto thread_table =
            dynamic_cast<libsinsp::state::built_in_table<int64_t> *>(
                    reg->get_table<int64_t>("threads"));
    auto field =
            thread_table->dynamic_fields()->fields().find(POD_UID_FIELD_NAME);
    auto fieldacc = field->second.new_accessor<std::string>();
    auto init_thread_entry = thread_table->get_entry(INIT_TID);
    ASSERT_NE(init_thread_entry, nullptr);
    std::string pod_uid = "";

    // CgroupV1, driver cgroup
    std::string expected_pod_uid = "05869489-8c7f-45dc-9abd-1b1620787bb1";
    generate_execve_enter_and_exit_event(
            0, INIT_TID, INIT_TID, INIT_PID, INIT_PTID, "init", "init",
            "/lib/systemd/systemd",
            {"cpuset=/kubepods/besteffort/pod" + expected_pod_uid +
             "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bb"
             "c"});

    // Check that the pod uid is updated after the first execve
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);

    // CgroupV1, driver systemd
    // systemd has this format with `_` instead of `-`
    expected_pod_uid = "0f90f31c_ebeb_4192_a2b0_92e076c43817";
    generate_execve_enter_and_exit_event(
            0, INIT_TID, INIT_TID, INIT_PID, INIT_PTID, "init", "init",
            "/lib/systemd/systemd",
            {"cpuset=/kubepods.slice/kubepods-besteffort.slice/"
             "kubepods-besteffort-pod" +
             expected_pod_uid +
             ".slice/"
             "4c97d83b89df14eea65dbbab1f506b405758341616ab75437d66fd8bab0e2be"
             "b"});
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    std::replace(expected_pod_uid.begin(), expected_pod_uid.end(), '_', '-');
    ASSERT_EQ(pod_uid, expected_pod_uid);

    // CgroupV2, driver cgroup
    expected_pod_uid = "af4fa4cf-129e-4699-a2af-65548fb8977d";
    generate_execve_enter_and_exit_event(
            0, INIT_TID, INIT_TID, INIT_PID, INIT_PTID, "init", "init",
            "/lib/systemd/systemd",
            {"cpuset=/kubepods/besteffort/pod" + expected_pod_uid +
             "/fc16540dcd776bb475437b722c47de798fa1b07687db1ba7d4609c23d5d1a08"
             "8"});
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);

    // CgroupV2, driver systemd
    expected_pod_uid = "43f23404_e33c_48c7_8114_28ee4b7043ec";
    generate_execve_enter_and_exit_event(
            0, INIT_TID, INIT_TID, INIT_PID, INIT_PTID, "init", "init",
            "/lib/systemd/systemd",
            {"cpuset=/kubepods.slice/kubepods-besteffort.slice/"
             "kubepods-besteffort-pod" +
             expected_pod_uid +
             ".slice/"
             "cri-containerd-"
             "b59ce319955234d0b051a93dac5efa8fc07df08d8b0188195b434174efc44e73."
             "scope"});
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    std::replace(expected_pod_uid.begin(), expected_pod_uid.end(), '_', '-');
    ASSERT_EQ(pod_uid, expected_pod_uid);

    // Not match, wrong pod_uid format
    // Use a cgroup with a wrong pod_uid
    generate_execve_enter_and_exit_event(
            0, INIT_TID, INIT_TID, INIT_PID, INIT_PTID, "init", "init",
            "/lib/systemd/systemd",
            {"cpuset=/kubepods.slice/kubepods-besteffort.slice/"
             "kubepods-besteffort-pod438943***343r2e-fsdwed-32ewad-e2dw-2."
             "slice/"
             "cri-containerd-"
             "b59ce319955234d0b051a93dac5efa8fc07df08d8b0188195b434174efc44e73."
             "scope"});
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    // We are not able to extract something valid from the last call so the
    // pod_uid is unchanged
    ASSERT_EQ(pod_uid, expected_pod_uid);
}

// Check that the plugin defines a new field called "pod_uid" in the `init`
// plugin.
TEST_F(sinsp_with_test_input, plugin_k8s_pod_uid_field_existance)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();
    open_inspector();

    // Check that the field is defined by the plugin in the init API
    auto &reg = m_inspector.get_table_registry();
    ASSERT_EQ(reg->tables().size(), 1);
    ASSERT_NE(reg->tables().find(THREAD_TABLE_NAME), reg->tables().end());
    auto thread_table =
            dynamic_cast<libsinsp::state::built_in_table<int64_t> *>(
                    reg->get_table<int64_t>("threads"));
    auto field =
            thread_table->dynamic_fields()->fields().find(POD_UID_FIELD_NAME);
    ASSERT_NE(field, thread_table->dynamic_fields()->fields().end());
    ASSERT_EQ(field->second.name(), POD_UID_FIELD_NAME);
    ASSERT_EQ(field->second.info(),
              libsinsp::state::typeinfo::of<std::string>());

    // Try to access this field for the init thread, the value should be empty
    // since the plugin doesn't populate it!
    auto fieldacc = field->second.new_accessor<std::string>();
    auto init_thread_entry = thread_table->get_entry(INIT_TID);
    ASSERT_NE(init_thread_entry, nullptr);
    std::string pod_uid;
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, "");
}

// Parametrized test for clone/fork events
class clone_fork_test : public sinsp_with_test_input,
                        public ::testing::WithParamInterface<ppm_event_code>
{
};

// Check that clone/fork events are correctly parsed into the plugin and the
// pod_uid is populated for the new thread!
TEST_P(clone_fork_test, plugin_k8s_clone_fork_parse)
{
    ppm_event_code event = GetParam();

    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist);
    add_default_init_thread();
    open_inspector();

    auto &reg = m_inspector.get_table_registry();
    auto thread_table =
            dynamic_cast<libsinsp::state::built_in_table<int64_t> *>(
                    reg->get_table<int64_t>("threads"));
    auto dynamic_fields = thread_table->dynamic_fields();
    auto field = dynamic_fields->fields().find(POD_UID_FIELD_NAME);
    auto fieldacc = field->second.new_accessor<std::string>();

    int64_t p1_tid = 2;
    int64_t p1_pid = 2;
    int64_t p1_ptid = INIT_TID;
    int64_t p1_vtid = 1;
    int64_t p1_vpid = 1;

    std::string expected_pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";

    /* We generate a clone exit event for the parent. */
    /* This is parsed but the pod_uid is not extracted. */
    auto evt = generate_clone_x_event(
            p1_tid, INIT_TID, INIT_PID, INIT_PTID, 0, INIT_TID, INIT_PTID,
            "init",
            {"cpuset=/kubepods/besteffort/pod" + expected_pod_uid +
             "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6b"
             "bc"},
            event);
    ASSERT_EQ(evt->get_type(), event);
    auto init_thread_entry = thread_table->get_entry(INIT_TID);
    ASSERT_NE(init_thread_entry, nullptr);
    std::string pod_uid;
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, "");

    evt = generate_clone_x_event(
            0, p1_tid, p1_pid, p1_ptid, PPM_CL_CHILD_IN_PIDNS, p1_vtid, p1_vpid,
            "bash",
            {"cpuset=/kubepods/besteffort/pod" + expected_pod_uid +
             "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6b"
             "bc"},
            event);
    ASSERT_EQ(evt->get_type(), event);

    auto p1_tid_entry = thread_table->get_entry(p1_tid);
    ASSERT_NE(p1_tid_entry, nullptr);
    p1_tid_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);
}

// Define the test parameters
INSTANTIATE_TEST_CASE_P(clone_fork_events, clone_fork_test,
                        ::testing::Values(PPME_SYSCALL_CLONE_20_X,
                                          PPME_SYSCALL_FORK_20_X,
                                          PPME_SYSCALL_VFORK_20_X,
                                          PPME_SYSCALL_CLONE3_X),
                        [](const ::testing::TestParamInfo<ppm_event_code> &info)
                        {
                            switch(info.param)
                            {
                            case PPME_SYSCALL_CLONE_20_X:
                                return "CLONE_20_X";
                            case PPME_SYSCALL_FORK_20_X:
                                return "FORK_20_X";
                            case PPME_SYSCALL_VFORK_20_X:
                                return "VFORK_20_X";
                            case PPME_SYSCALL_CLONE3_X:
                                return "CLONE3_X";
                            default:
                                return "UNKNOWN";
                            }
                        });

// Check that execve/execveat events are correctly parsed into the plugin and
// the pod_uid is populated for the new thread!
// TEST_F(sinsp_with_test_input, plugin_k8s_PPME_SYSCALL_EXECVE_19_X_parse)
//{
//    EXECVE_EXECVEAT_TEST(PPME_SYSCALL_EXECVE_19_X);
//}
//}
TEST_F(sinsp_with_test_input, plugin_k8s_PPME_SYSCALL_EXECVEAT_X_parse)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();
    open_inspector();

    auto &reg = m_inspector.get_table_registry();
    auto thread_table =
            dynamic_cast<libsinsp::state::built_in_table<int64_t> *>(
                    reg->get_table<int64_t>("threads"));
    auto dynamic_fields = thread_table->dynamic_fields();
    auto field = dynamic_fields->fields().find(POD_UID_FIELD_NAME);
    auto fieldacc = field->second.new_accessor<std::string>();

    uint64_t not_relevant_64 = 0;
    uint32_t not_relevant_32 = 0;

    std::string expected_pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
    std::vector<std::string> cgroups1 = {"cpuset=/kubepods/besteffort/pod" +
                                         expected_pod_uid +
                                         "/691e0ffb65010b2b611f3a15b7f76c4846"
                                         "6192e673e156f38bd2f8e25acd6bbc"};
    std::string cgroupsv = test_utils::to_null_delimited(cgroups1);
    scap_const_sized_buffer empty_bytebuf = {/*.buf =*/nullptr, /*.size =*/0};
    SCAP_EMPTY_PARAMS_SET(empty_params_set, 27);
    auto evt = add_event_advance_ts_with_empty_params(
            increasing_ts(), INIT_TID, PPME_SYSCALL_EXECVEAT_X,
            &empty_params_set, 30, not_relevant_64, "/bin/test-exe",
            empty_bytebuf, (uint64_t)1, (uint64_t)1, (uint64_t)1, "<NA>",
            not_relevant_64, not_relevant_64, not_relevant_64, 0, 0, 0,
            "test-exe",
            scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()},
            empty_bytebuf, 0, not_relevant_64, 0, 0, not_relevant_64,
            not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64,
            not_relevant_64, not_relevant_32, nullptr, not_relevant_64,
            not_relevant_32);
    ASSERT_EQ(evt->get_type(), PPME_SYSCALL_EXECVEAT_X);

    auto init_thread_entry = thread_table->get_entry(INIT_TID);
    ASSERT_NE(init_thread_entry, nullptr);
    std::string pod_uid;
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);
}

// Check that the pod_uid is correctly overwritten with an execve after a clone
TEST_F(sinsp_with_test_input, plugin_k8s_execve_after_clone_event)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();
    open_inspector();

    auto &reg = m_inspector.get_table_registry();
    auto thread_table =
            dynamic_cast<libsinsp::state::built_in_table<int64_t> *>(
                    reg->get_table<int64_t>("threads"));
    auto field =
            thread_table->dynamic_fields()->fields().find(POD_UID_FIELD_NAME);
    auto fieldacc = field->second.new_accessor<std::string>();

    int64_t p1_tid = 2;
    int64_t p1_pid = 2;
    int64_t p1_ptid = INIT_TID;
    int64_t p1_vtid = 1;
    int64_t p1_vpid = 1;

    // Populate the pod_uid with a fist clone event
    std::string expected_pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
    generate_clone_x_event(0, p1_tid, p1_pid, p1_ptid, PPM_CL_CHILD_IN_PIDNS,
                           p1_vtid, p1_vpid, "bash",
                           {"cpuset=/kubepods/besteffort/pod" +
                            expected_pod_uid +
                            "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38"
                            "bd2f8e25acd6bbc"},
                           PPME_SYSCALL_CLONE_20_X);

    auto p1_thread_entry = thread_table->get_entry(p1_tid);
    ASSERT_NE(p1_thread_entry, nullptr);
    std::string pod_uid = "";
    p1_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);

    // Re-Populate the pod_uid with a following execve event
    expected_pod_uid = "05869489-8c7f-45dc-9abd-1b1620787bb1";
    generate_execve_enter_and_exit_event(
            0, p1_tid, p1_tid, p1_pid, p1_ptid, "bash", "bash", "/usr/bin/bash",
            {"cpuset=/kubepods/besteffort/pod" + expected_pod_uid +
             "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6bb"
             "c"});

    // Check that the pod uid is updated after the first execve
    p1_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);
}

// Check if the thread entry is correctly removed after it is populated by the
// plugin
TEST_F(sinsp_with_test_input, plugin_k8s_check_thread_entry_is_removed)
{
    // Create a new child `p1_tid` using the same logic as the parametrized test
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist);
    add_default_init_thread();
    open_inspector();

    auto &reg = m_inspector.get_table_registry();
    auto thread_table =
            dynamic_cast<libsinsp::state::built_in_table<int64_t> *>(
                    reg->get_table<int64_t>("threads"));
    auto dynamic_fields = thread_table->dynamic_fields();
    auto field = dynamic_fields->fields().find(POD_UID_FIELD_NAME);
    auto fieldacc = field->second.new_accessor<std::string>();

    int64_t p1_tid = 2;
    int64_t p1_pid = 2;
    int64_t p1_ptid = INIT_TID;
    int64_t p1_vtid = 1;
    int64_t p1_vpid = 1;

    std::string expected_pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";

    auto evt = generate_clone_x_event(
            p1_tid, INIT_TID, INIT_PID, INIT_PTID, 0, INIT_TID, INIT_PTID,
            "init",
            {"cpuset=/kubepods/besteffort/pod" + expected_pod_uid +
             "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6b"
             "bc"},
            PPME_SYSCALL_CLONE_20_X);
    ASSERT_EQ(evt->get_type(), PPME_SYSCALL_CLONE_20_X);

    evt = generate_clone_x_event(
            0, p1_tid, p1_pid, p1_ptid, PPM_CL_CHILD_IN_PIDNS, p1_vtid, p1_vpid,
            "bash",
            {"cpuset=/kubepods/besteffort/pod" + expected_pod_uid +
             "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6b"
             "bc"},
            PPME_SYSCALL_CLONE_20_X);
    ASSERT_EQ(evt->get_type(), PPME_SYSCALL_CLONE_20_X);

    // Check that now we have 2 entries in the thread table
    ASSERT_EQ(thread_table->entries_count(), 2);
    const auto &thread_manager = m_inspector.m_thread_manager;
    auto p1_tid_tinfo = thread_manager->get_thread_ref(p1_tid, false).get();
    ASSERT_TRUE(p1_tid_tinfo);

    // Call a proc_exit and see if the thread is removed from the thread table
    remove_thread(p1_tid, INIT_TID);
    p1_tid_tinfo = thread_manager->get_thread_ref(p1_tid, false).get();
    ASSERT_FALSE(p1_tid_tinfo);

    // Now we should have only one entry in the thread table
    ASSERT_EQ(thread_table->entries_count(), 1);
}

TEST_F(sinsp_with_test_input, plugin_k8s_parse_parent_clone)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();
    open_inspector();

    auto &reg = m_inspector.get_table_registry();
    auto thread_table =
            dynamic_cast<libsinsp::state::built_in_table<int64_t> *>(
                    reg->get_table<int64_t>("threads"));
    auto field =
            thread_table->dynamic_fields()->fields().find(POD_UID_FIELD_NAME);
    auto fieldacc = field->second.new_accessor<std::string>();

    int64_t p1_tid = 2;
    int64_t p1_pid = 2;
    int64_t p1_ptid = INIT_TID;
    int64_t p1_vtid = 1;
    int64_t p1_vpid = 1;
    int64_t p2_tid = 3;

    // Create process p1, that is a child of init
    std::string expected_pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";
    generate_clone_x_event(0, p1_tid, p1_pid, p1_ptid, PPM_CL_CHILD_IN_PIDNS,
                           p1_vtid, p1_vpid, "bash",
                           {"cpuset=/kubepods/besteffort/pod" +
                            expected_pod_uid +
                            "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38"
                            "bd2f8e25acd6bbc"},
                           PPME_SYSCALL_CLONE_20_X);
    auto p1_thread_entry = thread_table->get_entry(p1_tid);
    ASSERT_NE(p1_thread_entry, nullptr);
    std::string pod_uid = "";
    p1_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);

    // we clear the pod_uid manually so we check that the pod_uid will be
    // populated by the next clone parent event.
    std::string empty_pod_uid = "";
    p1_thread_entry->set_dynamic_field(fieldacc, empty_pod_uid);
    p1_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, empty_pod_uid);

    // Clone parent exit event for p1
    generate_clone_x_event(p2_tid, p1_tid, p1_pid, p1_ptid,
                           PPM_CL_CHILD_IN_PIDNS, p1_vtid, p1_vpid, "bash",
                           {"cpuset=/kubepods/besteffort/pod" +
                            expected_pod_uid +
                            "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38"
                            "bd2f8e25acd6bbc"},
                           PPME_SYSCALL_CLONE_20_X);
    // We have again the pod_uid for the parent thread
    p1_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);
}

TEST_F(sinsp_with_test_input, plugin_listen_cap_poduid)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();

    std::string expected_pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";

    // Take default init thread and set a cgroup on it
    auto &tinfo = m_threads.at(0);
    strcpy(tinfo.cgroups.path,
           std::string("cpuset=/kubepods/besteffort/pod" + expected_pod_uid +
                       "/691e0ffb65010b2b611f3a15b7f76c4846"
                       "6192e673e156f38bd2f8e25acd6bbc\0")
                   .c_str());
    tinfo.cgroups.len = strlen(tinfo.cgroups.path);

    // This will trigger `capture_open` listening CAP
    // that will write the poduid for the existing tinfo
    open_inspector();

    auto &reg = m_inspector.get_table_registry();
    auto thread_table =
            dynamic_cast<libsinsp::state::built_in_table<int64_t> *>(
                    reg->get_table<int64_t>("threads"));
    auto dynamic_fields = thread_table->dynamic_fields();
    auto field = dynamic_fields->fields().find(POD_UID_FIELD_NAME);
    auto fieldacc = field->second.new_accessor<std::string>();

    auto init_thread_entry = thread_table->get_entry(INIT_TID);
    ASSERT_NE(init_thread_entry, nullptr);
    std::string pod_uid;
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);
    ASSERT_EQ(pod_uid, expected_pod_uid);
}
