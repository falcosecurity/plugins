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
#define CLONE_FORK_TEST(event)                                                 \
    std::shared_ptr<sinsp_plugin> plugin_owner;                                \
    filter_check_list pl_flist;                                                \
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)                       \
    add_default_init_thread();                                                 \
    open_inspector();                                                          \
                                                                               \
    auto &reg = m_inspector.get_table_registry();                              \
    auto thread_table = reg->get_table<int64_t>(THREAD_TABLE_NAME);            \
    auto dynamic_fields = thread_table->dynamic_fields();                      \
    auto field = dynamic_fields->fields().find(POD_UID_FIELD_NAME);            \
    auto fieldacc = field->second.new_accessor<std::string>();                 \
                                                                               \
    int64_t p1_tid = 2;                                                        \
    int64_t p1_pid = 2;                                                        \
    int64_t p1_ptid = INIT_TID;                                                \
    int64_t p1_vtid = 1;                                                       \
    int64_t p1_vpid = 1;                                                       \
                                                                               \
    std::string expected_pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";     \
    auto evt = generate_clone_x_event(                                         \
            0, p1_tid, p1_pid, p1_ptid, PPM_CL_CHILD_IN_PIDNS, p1_vtid,        \
            p1_vpid, "bash",                                                   \
            {"cpuset=/kubepods/besteffort/pod" + expected_pod_uid +            \
             "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6b" \
             "bc"},                                                            \
            event);                                                            \
    ASSERT_EQ(evt->get_type(), event);                                         \
                                                                               \
    auto init_thread_entry = thread_table->get_entry(p1_tid);                  \
    ASSERT_NE(init_thread_entry, nullptr);                                     \
    std::string pod_uid;                                                       \
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);                   \
    ASSERT_EQ(pod_uid, expected_pod_uid);

#define EXECVE_EXECVEAT_TEST(event)                                            \
    std::shared_ptr<sinsp_plugin> plugin_owner;                                \
    filter_check_list pl_flist;                                                \
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)                       \
                                                                               \
    add_default_init_thread();                                                 \
    open_inspector();                                                          \
                                                                               \
    auto &reg = m_inspector.get_table_registry();                              \
    auto thread_table = reg->get_table<int64_t>(THREAD_TABLE_NAME);            \
    auto dynamic_fields = thread_table->dynamic_fields();                      \
    auto field = dynamic_fields->fields().find(POD_UID_FIELD_NAME);            \
    auto fieldacc = field->second.new_accessor<std::string>();                 \
                                                                               \
    uint64_t not_relevant_64 = 0;                                              \
    uint32_t not_relevant_32 = 0;                                              \
                                                                               \
    std::string expected_pod_uid = "5eaeeca9-2277-460b-a4bf-5a0783f6d49f";     \
    std::vector<std::string> cgroups1 = {"cpuset=/kubepods/besteffort/pod" +   \
                                         expected_pod_uid +                    \
                                         "/691e0ffb65010b2b611f3a15b7f76c4846" \
                                         "6192e673e156f38bd2f8e25acd6bbc"};    \
    std::string cgroupsv = test_utils::to_null_delimited(cgroups1);            \
    scap_const_sized_buffer empty_bytebuf = {/*.buf =*/nullptr, /*.size =*/0}; \
                                                                               \
    auto evt = add_event_advance_ts(                                           \
            increasing_ts(), INIT_TID, event, 27, (int64_t)0, "/bin/test-exe", \
            empty_bytebuf, INIT_TID, INIT_PID, INIT_PTID, "", not_relevant_64, \
            not_relevant_64, not_relevant_64, not_relevant_32,                 \
            not_relevant_32, not_relevant_32, "test-exe",                      \
            scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()},         \
            empty_bytebuf, not_relevant_32, not_relevant_64, not_relevant_32,  \
            (int32_t)PPM_EXE_WRITABLE, not_relevant_64, not_relevant_64,       \
            not_relevant_64, not_relevant_64, not_relevant_64,                 \
            not_relevant_64, not_relevant_32);                                 \
    ASSERT_EQ(evt->get_type(), event);                                         \
                                                                               \
    auto init_thread_entry = thread_table->get_entry(INIT_TID);                \
    ASSERT_NE(init_thread_entry, nullptr);                                     \
    std::string pod_uid;                                                       \
    init_thread_entry->get_dynamic_field(fieldacc, pod_uid);                   \
    ASSERT_EQ(pod_uid, expected_pod_uid);

// Check pod regex with different formats
TEST_F(sinsp_with_test_input, plugin_k8s_pod_uid_regex)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();
    open_inspector();

    auto &reg = m_inspector.get_table_registry();
    auto thread_table = reg->get_table<int64_t>(THREAD_TABLE_NAME);
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
    // We are not able to extract something valid from the cgroup so we set the
    // pod_uid to `""` in the plugin
    ASSERT_EQ(pod_uid, "");
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
    auto thread_table = reg->get_table<int64_t>(THREAD_TABLE_NAME);
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

// Check that clone/fork events are correctly parsed into the plugin and the
// pod_uid is populated for the new thread!
TEST_F(sinsp_with_test_input, plugin_k8s_PPME_SYSCALL_CLONE_20_X_parse)
{
    CLONE_FORK_TEST(PPME_SYSCALL_CLONE_20_X);
}

TEST_F(sinsp_with_test_input, plugin_k8s_PPME_SYSCALL_FORK_20_X_parse)
{
    CLONE_FORK_TEST(PPME_SYSCALL_FORK_20_X);
}

TEST_F(sinsp_with_test_input, plugin_k8s_PPME_SYSCALL_VFORK_20_X_parse)
{
    CLONE_FORK_TEST(PPME_SYSCALL_VFORK_20_X);
}

TEST_F(sinsp_with_test_input, plugin_k8s_PPME_SYSCALL_CLONE3_X_parse)
{
    CLONE_FORK_TEST(PPME_SYSCALL_CLONE3_X);
}

// Check that execve/execveat events are correctly parsed into the plugin and
// the pod_uid is populated for the new thread!
TEST_F(sinsp_with_test_input, plugin_k8s_PPME_SYSCALL_EXECVE_19_X_parse)
{
    EXECVE_EXECVEAT_TEST(PPME_SYSCALL_EXECVE_19_X);
}

TEST_F(sinsp_with_test_input, plugin_k8s_PPME_SYSCALL_EXECVEAT_X_parse)
{
    EXECVE_EXECVEAT_TEST(PPME_SYSCALL_EXECVEAT_X);
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
    auto thread_table = reg->get_table<int64_t>(THREAD_TABLE_NAME);
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
    // Create a new child `p1_tid`
    CLONE_FORK_TEST(PPME_SYSCALL_CLONE_20_X);

    // Check that now we have 2 entries in the thread table
    ASSERT_EQ(thread_table->entries_count(), 2);
    auto p1_tid_tinfo = m_inspector.get_thread_ref(p1_tid, false).get();
    ASSERT_TRUE(p1_tid_tinfo);

    // Call a proc_exit and see if the thread is removed from the thread table
    remove_thread(p1_tid, INIT_TID);
    p1_tid_tinfo = m_inspector.get_thread_ref(p1_tid, false).get();
    ASSERT_FALSE(p1_tid_tinfo);

    // Now we should have only one entry in the thread table
    ASSERT_EQ(thread_table->entries_count(), 1);
}
