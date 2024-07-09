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

#include <gtest/gtest.h>
#include <sinsp_with_test_input.h>
#include <helpers/threads_helpers.h>
#include <num/cms.h>
#include <plugin_test_var.h>
#include <test_helpers.h>

TEST(plugin_anomalydetection, plugin_anomalydetection_cms_dim)
{
    double gamma = 0.001;
    double epsilon = 0.0001;
    uint64_t d = 7;
    uint64_t w = 27183;

    plugin::anomalydetection::num::cms<uint64_t> cms_proba_init(gamma, epsilon);

    EXPECT_EQ(cms_proba_init.get_d(), d);
    EXPECT_EQ(cms_proba_init.get_w(), w);
    EXPECT_DOUBLE_EQ(cms_proba_init.get_gamma(), gamma);
    EXPECT_DOUBLE_EQ(cms_proba_init.get_eps(), epsilon);

    plugin::anomalydetection::num::cms<uint64_t> cms_dim_init(d, w);

    EXPECT_EQ(cms_dim_init.get_d(), d);
    EXPECT_EQ(cms_dim_init.get_w(), w);
    auto gamma_rounded = round(cms_dim_init.get_gamma() * 1000.0) / 1000.0;
    auto eps_rounded = round(cms_dim_init.get_eps() * 10000.0) / 10000.0;
    EXPECT_DOUBLE_EQ(gamma_rounded, gamma);
    EXPECT_DOUBLE_EQ(eps_rounded, epsilon);
}

TEST(plugin_anomalydetection, plugin_anomalydetection_cms_update_estimate)
{
    double gamma = 0.001;
    double epsilon = 0.0001;

    plugin::anomalydetection::num::cms<uint64_t> cms(gamma, epsilon);

    std::string test_str = "falco";
    std::string test_str2 = "falco1";
    cms.update(test_str, 1);
    cms.update(test_str, 1);
    cms.update(test_str, 1);

    EXPECT_EQ(cms.estimate(test_str), 3);
    EXPECT_EQ(cms.estimate(test_str2), 0);
}

TEST_F(sinsp_with_test_input, plugin_anomalydetection_filterchecks_fields)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)

    add_default_init_thread();
    open_inspector();

    /* Create realistic spawn_process event, adopted from libs unit test */
    sinsp_evt* evt = NULL;
    uint64_t parent_pid = 1, parent_tid = 1, child_pid = 20, child_tid = 20, null_pid = 0;
    uint64_t fdlimit = 1024, pgft_maj = 0, pgft_min = 1;
    uint64_t exe_ino = 242048, ctime = 1676262698000004588, mtime = 1676262698000004577;
    uint32_t loginuid = UINT32_MAX - 1, euid = 2000U;
    scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};

    add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_E, 0);
    std::vector<std::string> cgroups = {"cpuset=/", "cpu=/user.slice", "cpuacct=/user.slice", "io=/user.slice", "memory=/user.slice/user-1000.slice/session-1.scope", "devices=/user.slice", "freezer=/", "net_cls=/", "perf_event=/", "net_prio=/", "hugetlb=/", "pids=/user.slice/user-1000.slice/session-1.scope", "rdma=/", "misc=/"};
    std::string cgroupsv = test_utils::to_null_delimited(cgroups);
    std::vector<std::string> env = {"SHELL=/bin/bash", "SHELL_NEW=/bin/sh", "PWD=/home/user", "HOME=/home/user"};
    std::string envv = test_utils::to_null_delimited(env);
    std::vector<std::string> args = {"-c", "'echo aGVsbG8K | base64 -d'"};
    std::string argsv = test_utils::to_null_delimited(args);

    add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, parent_pid, "bash", empty_bytebuf, parent_pid, parent_tid, null_pid, "", fdlimit, pgft_maj, pgft_min, (uint32_t)12088, (uint32_t)7208, (uint32_t)0, "init", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t)(PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID), (uint32_t)1000, (uint32_t)1000, parent_pid, parent_tid);
    add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, (uint64_t)0, "bash", empty_bytebuf, child_pid, child_tid, parent_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t)12088, (uint32_t)3764, (uint32_t)0, "init", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t)(PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID), (uint32_t)1000, (uint32_t)1000, child_pid, child_tid);
    add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");
    evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t)0, "/bin/test-exe", scap_const_sized_buffer{argsv.data(), argsv.size()}, child_tid, child_pid, parent_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t)29612, (uint32_t)4, (uint32_t)0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, (int32_t)34818, parent_pid, loginuid, (int32_t) PPM_EXE_WRITABLE, parent_pid, parent_pid, parent_pid, exe_ino, ctime, mtime, euid);

    ASSERT_EQ(get_field_as_string(evt, "proc.name"), "test-exe");

    /* Check anomalydetection plugin filter fields */
    ASSERT_TRUE(field_exists(evt, "anomaly.count_min_sketch", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch", pl_flist), "1");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch[0]", pl_flist), "1");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch[1]", pl_flist), "0");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch[2]", pl_flist), "1");

    ASSERT_TRUE(field_exists(evt, "anomaly.count_min_sketch.profile", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile", pl_flist), "test-exeinit/bin/test-exe/sbin/init3481820");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[0]", pl_flist), "test-exeinit/bin/test-exe/sbin/init3481820");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "test-exeinit/bin/test-exe34818initinit");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[2]", pl_flist), "test-exe -c 'echo aGVsbG8K | base64 -d'test-exetest-exeinit20201/bin/test-exe/bin/test-exe/sbin/init1init0init");
}

TEST_F(sinsp_with_test_input, plugin_anomalydetection_filterchecks_fields_proc_lineage)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)
    uint64_t not_relevant_64 = 0;
    uint32_t not_relevant_32 = 0;
    uint64_t pgid = 9999;
    uint32_t loginuid = UINT32_MAX - 1, euid = 2000U;
    scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};
    std::vector<std::string> args = {"-c", "'echo aGVsbG8K | base64 -d'"};
    std::string argsv = test_utils::to_null_delimited(args);
    /* Instantiate the default tree */
    DEFAULT_TREE
    generate_execve_enter_and_exit_event(0, p2_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid, "/p2_t1_exepath", "p2_t1_comm", "/usr/bin/p2_t1_exepath");
    generate_execve_enter_and_exit_event(0, p3_t1_tid, p3_t1_tid, p3_t1_pid, p3_t1_ptid, "/p3_t1_exepath", "p3_t1_comm", "/usr/bin/p3_t1_exepath");
    generate_execve_enter_and_exit_event(0, p4_t1_tid, p4_t1_tid, p4_t1_pid, p4_t1_ptid, "/p4_t1_exepath", "p4_t1_comm", "/usr/bin/p4_t1_exepath");
    generate_execve_enter_and_exit_event(0, p4_t2_tid, p4_t1_tid, p4_t1_pid, p4_t1_ptid, "/p4_t1_exepath", "p4_t1_comm", "/usr/bin/p4_t1_exepath");

    add_event_advance_ts(increasing_ts(), p5_t1_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/usr/bin/p5_t1_exepath");
    add_event_advance_ts(increasing_ts(), p5_t1_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t)0, "/usr/bin/p5_t1_exepath", scap_const_sized_buffer{argsv.data(), argsv.size()}, p5_t1_tid, p5_t1_tid, p5_t1_ptid, "", not_relevant_64, not_relevant_64, not_relevant_64, (uint32_t)29612, (uint32_t)4, (uint32_t)0, "p5_t1_comm", empty_bytebuf, empty_bytebuf, (int32_t)34818, pgid, loginuid, (int32_t) PPM_EXE_WRITABLE, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, euid);
    add_event_advance_ts(increasing_ts(), p6_t1_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/usr/bin/p6_t1_exepath");
    auto evt = add_event_advance_ts(increasing_ts(), p6_t1_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t)0, "/usr/bin/p6_t1_exepath", scap_const_sized_buffer{argsv.data(), argsv.size()}, p6_t1_tid, p6_t1_tid, p6_t1_ptid, "", not_relevant_64, not_relevant_64, not_relevant_64, (uint32_t)29612, (uint32_t)4, (uint32_t)0, "p6_t1_comm", empty_bytebuf, empty_bytebuf, (int32_t)34818, pgid, loginuid, (int32_t) PPM_EXE_WRITABLE, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, euid);

    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[2]", pl_flist), "p6_t1_comm -c 'echo aGVsbG8K | base64 -d'p6_t1_commp6_t1_commp5_t1_commp4_t1_commp3_t1_commp2_t1_comminit8787827672251/usr/bin/p6_t1_exepath/usr/bin/p6_t1_exepath/usr/bin/p5_t1_exepath/usr/bin/p4_t1_exepath/usr/bin/p3_t1_exepath/usr/bin/p2_t1_exepath/sbin/init9999p5_t1_comm0init");
}
