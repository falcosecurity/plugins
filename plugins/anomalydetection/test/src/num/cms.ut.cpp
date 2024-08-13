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
    std::vector<std::string> cgroups = {"cgroups=cpuset=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "cpu=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "cpuacct=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "io=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "memory=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "devices=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "freezer=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "net_cls=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "perf_event=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "net_prio=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "hugetlb=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "pids=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "rdma=/docker/f9c7a020960a15738167a77594bff1f7ac5f5bfdb6646ecbc9b17c7ed7ec5066", "misc=/"};
    std::string cgroupsv = test_utils::to_null_delimited(cgroups);
    std::vector<std::string> env = {"SHELL=/bin/bash", "SHELL_NEW=/bin/sh", "PWD=/home/user", "HOME=/home/user"};
    std::string envv = test_utils::to_null_delimited(env);
    std::vector<std::string> args = {"-c", "'echo aGVsbG8K | base64 -d'"};
    std::string argsv = test_utils::to_null_delimited(args);

    add_event_advance_ts(increasing_ts(), parent_tid, PPME_SYSCALL_CLONE_20_X, 20, parent_pid, "bash", empty_bytebuf, parent_pid, parent_tid, null_pid, "", fdlimit, pgft_maj, pgft_min, (uint32_t)12088, (uint32_t)7208, (uint32_t)0, "init", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t)(PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID | PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS), (uint32_t)1000, (uint32_t)1000, parent_pid, parent_tid);
    add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_CLONE_20_X, 20, (uint64_t)0, "bash", empty_bytebuf, child_pid, child_tid, parent_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t)12088, (uint32_t)3764, (uint32_t)0, "init", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, (uint32_t)(PPM_CL_CLONE_CHILD_CLEARTID | PPM_CL_CLONE_CHILD_SETTID | PPM_CL_CLONE_NEWPID | PPM_CL_CHILD_IN_PIDNS), (uint32_t)1000, (uint32_t)1000, child_pid, child_tid);
    add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/bin/test-exe");
    evt = add_event_advance_ts(increasing_ts(), child_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t)0, "/bin/test-exe", scap_const_sized_buffer{argsv.data(), argsv.size()}, child_tid, child_pid, parent_tid, "", fdlimit, pgft_maj, pgft_min, (uint32_t)29612, (uint32_t)4, (uint32_t)0, "test-exe", scap_const_sized_buffer{cgroupsv.data(), cgroupsv.size()}, scap_const_sized_buffer{envv.data(), envv.size()}, (int32_t)34818, child_tid, loginuid, (uint32_t) (PPM_EXE_WRITABLE | PPM_EXE_UPPER_LAYER), parent_pid, parent_pid, parent_pid, exe_ino, ctime, mtime, euid);

    ASSERT_EQ(get_field_as_string(evt, "proc.name"), "test-exe");

    /* Check anomalydetection plugin filter fields */
    ASSERT_TRUE(field_exists(evt, "anomaly.count_min_sketch", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch", pl_flist), "1");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch[0]", pl_flist), "1");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch[1]", pl_flist), "0");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch[2]", pl_flist), "1");

    ASSERT_TRUE(field_exists(evt, "anomaly.count_min_sketch.profile", pl_flist));
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile", pl_flist), "1024204816762626980000045881676262698000004577110229/home/user/bin/test-exe -c 'echo aGVsbG8K | base64 -d'test-exeinit/bin/test-exe/sbin/init34818201");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[0]", pl_flist), "1024204816762626980000045881676262698000004577110229/home/user/bin/test-exe -c 'echo aGVsbG8K | base64 -d'test-exeinit/bin/test-exe/sbin/init34818201");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[2]", pl_flist), "test-exeinit/bin/test-exe/sbin/init/bin/test-exe/sbin/inittest-exe -c 'echo aGVsbG8K | base64 -d'test-exe -c 'echo aGVsbG8K | base64 -d'initinittest-exetest-exeinit20201/bin/test-exe/bin/test-exe/sbin/init20test-exe/bin/test-exe/bin/test-exe0init/sbin/init/sbin/init");
}

TEST_F(sinsp_with_test_input, plugin_anomalydetection_filterchecks_fields_proc_lineage)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)
    uint64_t not_relevant_64 = 0;
    uint64_t pgid = 9999;
    uint32_t loginuid = UINT32_MAX - 1, euid = 2000U;
    scap_const_sized_buffer empty_bytebuf = {.buf = nullptr, .size = 0};
    std::vector<std::string> args = {"-c", "cat test"};
    std::string argsv = test_utils::to_null_delimited(args);
    /* Instantiate the default tree */
    DEFAULT_TREE
    generate_execve_enter_and_exit_event(0, p2_t1_tid, p2_t1_tid, p2_t1_pid, p2_t1_ptid, "/p2_t1_exepath", "p2_t1_comm", "/usr/bin/p2_t1_exepath");
    generate_execve_enter_and_exit_event(0, p3_t1_tid, p3_t1_tid, p3_t1_pid, p3_t1_ptid, "/p3_t1_exepath", "p3_t1_comm", "/usr/bin/p3_t1_exepath");
    generate_execve_enter_and_exit_event(0, p4_t1_tid, p4_t1_tid, p4_t1_pid, p4_t1_ptid, "/p4_t1_exepath", "p4_t1_comm", "/usr/bin/p4_t1_exepath");
    generate_execve_enter_and_exit_event(0, p4_t2_tid, p4_t1_tid, p4_t1_pid, p4_t1_ptid, "/p4_t1_exepath", "p4_t1_comm", "/usr/bin/p4_t1_exepath");

    add_event_advance_ts(increasing_ts(), p5_t1_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/usr/bin/p5_t1_exepath");
    add_event_advance_ts(increasing_ts(), p5_t1_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t)0, "/usr/bin/p5_t1_exepath", scap_const_sized_buffer{argsv.data(), argsv.size()}, p5_t1_tid, p5_t1_tid, p5_t1_ptid, "", not_relevant_64, not_relevant_64, not_relevant_64, (uint32_t)29612, (uint32_t)4, (uint32_t)0, "p5_t1_comm", empty_bytebuf, empty_bytebuf, (int32_t)34818, pgid, loginuid, (int32_t) PPM_EXE_WRITABLE, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, euid);
    args = {"-c", "'echo aGVsbG8K | base64 -d'"};
    add_event_advance_ts(increasing_ts(), p6_t1_tid, PPME_SYSCALL_EXECVE_19_E, 1, "/usr/bin/p6_t1_exepath");
    auto evt = add_event_advance_ts(increasing_ts(), p6_t1_tid, PPME_SYSCALL_EXECVE_19_X, 27, (int64_t)0, "/usr/bin/p6_t1_exepath", scap_const_sized_buffer{argsv.data(), argsv.size()}, p6_t1_tid, p6_t1_tid, p6_t1_ptid, "", not_relevant_64, not_relevant_64, not_relevant_64, (uint32_t)29612, (uint32_t)4, (uint32_t)0, "p6_t1_comm", empty_bytebuf, empty_bytebuf, (int32_t)34818, pgid, loginuid, (int32_t) PPM_EXE_WRITABLE, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, not_relevant_64, euid);

    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[2]", pl_flist), "p6_t1_commp5_t1_commp4_t1_commp3_t1_commp2_t1_comminit/usr/bin/p6_t1_exepath/usr/bin/p5_t1_exepath/p4_t1_exepath/p3_t1_exepath/p2_t1_exepath/sbin/init/usr/bin/p6_t1_exepath/usr/bin/p5_t1_exepath/usr/bin/p4_t1_exepath/usr/bin/p3_t1_exepath/usr/bin/p2_t1_exepath/sbin/initp6_t1_comm -c cat testp6_t1_comm -c cat testp5_t1_comm -c cat testp5_t1_comm -c cat testp6_t1_commp6_t1_commp5_t1_commp4_t1_commp3_t1_commp2_t1_comminit8787827672251/usr/bin/p6_t1_exepath/usr/bin/p6_t1_exepath/usr/bin/p5_t1_exepath/usr/bin/p4_t1_exepath/usr/bin/p3_t1_exepath/usr/bin/p2_t1_exepath/sbin/init9999p5_t1_comm/usr/bin/p5_t1_exepath/usr/bin/p5_t1_exepath0init/sbin/init/sbin/init");
}

TEST_F(sinsp_with_test_input, plugin_anomalydetection_filterchecks_fields_fd)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)
    add_default_init_thread();

    sinsp_evt *evt;
    open_inspector();

    uint64_t ino = 777;
    int64_t fd = 4;
    add_event(increasing_ts(), 3, PPME_SYSCALL_OPEN_E, 3, "/tmp/subdir1/subdir2/subdir3/subdir4/../../the_file", 0, 0);
    add_event_advance_ts(increasing_ts(), 3, PPME_SYSCALL_OPEN_X, 6, fd, "/tmp/../../../some_other_file", 0, 0, 0, ino);
    fd = 5;
    add_event(increasing_ts(), 3, PPME_SYSCALL_OPEN_E, 3, "/tmp/subdir1/subdir2/subdir3/subdir4/../../the_file2", 0, 0);
    evt = add_event_advance_ts(increasing_ts(), 3, PPME_SYSCALL_OPEN_X, 6, fd, "/tmp/../../../some_other_file2", 0, 0, 0, ino);
    ASSERT_EQ(get_field_as_string(evt, "fd.num"), "5");
    ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/subdir1/subdir2/the_file2");
    ASSERT_EQ(get_field_as_string(evt, "fd.directory"), "/tmp/subdir1/subdir2");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "-15/tmp/subdir1/subdir2/the_file2/tmp/subdir1/subdir2the_file20777/tmp/subdir1/subdir2/subdir3/subdir4/../../the_file2");

    evt = NULL;
    uint64_t dirfd = 3, new_fd = 100;
    add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT2_E, 5, dirfd, "<NA>", 0, 0, 0);
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT2_X, 8, new_fd, dirfd, "/tmp/dir1/../the_file", 0, 0, 0, 0, ino);
    ASSERT_EQ(get_field_as_string(evt, "proc.pid"), "1");
    ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/the_file");
    ASSERT_EQ(get_field_as_string(evt, "fd.nameraw"), "/tmp/dir1/../the_file");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "1100/tmp/the_file/tmpthe_file0777/tmp/dir1/../the_file");

    evt = NULL;
    fd = 4;
    int64_t mountfd = 5;
    add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 6, fd, mountfd, PPM_O_RDWR, "/tmp/open_handle.txt", 0, ino);
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "14/tmp/open_handle.txt/tmpopen_handle.txt0777/tmp/open_handle.txt");
}

TEST_F(sinsp_with_test_input, plugin_anomalydetection_filterchecks_fields_fd_null_fd_table)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)
    add_default_init_thread();

    sinsp_evt *evt;
    open_inspector();

    uint64_t ino = 777;
    int64_t fd = 4;
    add_event(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "subdir1//../the_file2", 0, 0);
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, "subdir1//../the_file2", 0, 0, 0, ino);

    sinsp_fdinfo* fdinfo = evt->get_thread_info()->get_fd(fd);
    ASSERT_EQ(get_field_as_string(evt, "fd.num"), "4");
    ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/root/the_file2");
    ASSERT_EQ(get_field_as_string(evt, "proc.cwd"), "/root/");
    fdinfo->m_name.clear();
    fdinfo->m_name_raw.clear();
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "14/root/the_file2/rootthe_file20777subdir1//../the_file2");

    evt = NULL;
    uint64_t dirfd = 8, new_fd = 100;
    fd = 8;
    add_event(increasing_ts(), 1, PPME_SYSCALL_OPEN_E, 3, "/tmp/subdir1/subdir2/../the_file2", 0, 0);
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_X, 6, fd, "/tmp/subdir1/subdir2/../the_file2", 0, 0, 0, ino);
    add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT2_E, 5, dirfd, "subdir1//../the_file", 0, 0, 0);
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPENAT2_X, 8, new_fd, dirfd, "subdir1//../the_file", 0, 0, 0, 0, ino);
    ASSERT_EQ(get_field_as_string(evt, "fd.num"), "100");
    ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/subdir1/the_file2/the_file");
    ASSERT_EQ(get_field_as_string(evt, "fs.path.name"), "/root/the_file"); // todo fix in libs as its wrong
    ASSERT_EQ(get_field_as_string(evt, "proc.cwd"), "/root/");
    fdinfo = evt->get_thread_info()->get_fd(new_fd);
    fdinfo->m_name.clear();
    fdinfo->m_name_raw.clear();
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "1100/tmp/subdir1/the_file/tmp/subdir1the_file0777subdir1//../the_file");

    evt = NULL;
    fd = 4;
    int64_t mountfd = 5;
    add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_E, 0);
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SYSCALL_OPEN_BY_HANDLE_AT_X, 6, fd, mountfd, PPM_O_RDWR, "/tmp/open_handle.txt", 0, ino);
    ASSERT_EQ(get_field_as_string(evt, "fd.num"), "4");
    ASSERT_EQ(get_field_as_string(evt, "fd.name"), "/tmp/open_handle.txt");
    ASSERT_EQ(get_field_as_string(evt, "proc.cwd"), "/root/");
    fdinfo = evt->get_thread_info()->get_fd(fd);
    fdinfo->m_name.clear();
    fdinfo->m_name_raw.clear();
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "14/tmp/open_handle.txt/tmpopen_handle.txt0777/tmp/open_handle.txt");
}

TEST_F(sinsp_with_test_input, plugin_anomalydetection_filterchecks_fields_fd_network)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)
    add_default_init_thread();

    open_inspector();
    sinsp_evt* evt = NULL;
    sinsp_fdinfo* fdinfo = NULL;
    int64_t client_fd = 8;
    int64_t return_value = 0;

    add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_STREAM, (uint32_t) 0);
    add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

    sockaddr_in client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);
    sockaddr_in server = test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);

    std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});
    std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

    /* We are able to recover the fdinfo in the connect exit event even when interleaved */
    fdinfo = evt->get_fd_info();
    ASSERT_NE(fdinfo, nullptr);

    ASSERT_EQ(get_field_as_string(evt, "fd.connected"), "true");
    ASSERT_EQ(get_field_as_string(evt, "fd.name"), "172.40.111.222:54321->142.251.111.147:443");
    ASSERT_EQ(get_field_as_string(evt, "fd.rip"), "172.40.111.222");
    ASSERT_EQ(get_field_as_string(evt, "fd.lip"), "142.251.111.147");
    ASSERT_EQ(get_field_as_string(evt, "fd.cip"), "172.40.111.222");
    ASSERT_EQ(get_field_as_string(evt, "fd.sip"), "142.251.111.147");
    ASSERT_EQ(get_field_as_string(evt, "fd.num"), "8");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "1172.40.111.222:54321142.251.111.147:4438172.40.111.222:54321->142.251.111.147:443");

    client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);
    std::vector<uint8_t> st = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));

    int64_t new_connected_fd = 6;
    add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_E, 0);
    add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_X, 5, new_connected_fd, scap_const_sized_buffer{st.data(), st.size()}, (uint8_t) 0, (uint32_t) 0, (uint32_t) 5);
    ASSERT_EQ(get_field_as_string(evt, "fd.name"), "172.40.111.222:54321->142.251.111.147:443");
    ASSERT_EQ(get_field_as_string(evt, "fd.num"), "6");
    ASSERT_EQ(get_field_as_string(evt, "fd.rip"), "172.40.111.222");
    ASSERT_EQ(get_field_as_string(evt, "fd.lip"), "142.251.111.147");
    ASSERT_EQ(get_field_as_string(evt, "fd.cip"), "172.40.111.222");
    ASSERT_EQ(get_field_as_string(evt, "fd.sip"), "142.251.111.147");
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "1172.40.111.222:54321142.251.111.147:4436172.40.111.222:54321->142.251.111.147:443");
}

TEST_F(sinsp_with_test_input, plugin_anomalydetection_filterchecks_fields_fd_network_null_fd_table)
{
    std::shared_ptr<sinsp_plugin> plugin_owner;
    filter_check_list pl_flist;
    ASSERT_PLUGIN_INITIALIZATION(plugin_owner, pl_flist)
    add_default_init_thread();

    open_inspector();
    sinsp_evt* evt = NULL;
    sinsp_fdinfo* fdinfo = NULL;
    int64_t client_fd = 8;
    int64_t return_value = 0;

    add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_E, 3, (uint32_t) PPM_AF_INET, (uint32_t) SOCK_STREAM, (uint32_t) 0);
    add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_SOCKET_X, 1, client_fd);

    sockaddr_in client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);
    sockaddr_in server = test_utils::fill_sockaddr_in(DEFAULT_SERVER_PORT, DEFAULT_IPV4_SERVER_STRING);

    std::vector<uint8_t> server_sockaddr = test_utils::pack_sockaddr(reinterpret_cast<sockaddr*>(&server));
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_E, 2, client_fd, scap_const_sized_buffer{server_sockaddr.data(), server_sockaddr.size()});
    std::vector<uint8_t> socktuple = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));
    evt = add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_CONNECT_X, 3, return_value, scap_const_sized_buffer{socktuple.data(), socktuple.size()}, client_fd);

    /* We are able to recover the fdinfo in the connect exit event even when interleaved */
    fdinfo = evt->get_fd_info();
    fdinfo->m_name.clear();
    fdinfo->m_name_raw.clear();
    ASSERT_NE(fdinfo, nullptr);
    ASSERT_EQ(get_field_as_string(evt, "fd.num"), "8");
    // no fallbacks atm
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "18");

    client = test_utils::fill_sockaddr_in(DEFAULT_CLIENT_PORT, DEFAULT_IPV4_CLIENT_STRING);
    std::vector<uint8_t> st = test_utils::pack_socktuple(reinterpret_cast<sockaddr*>(&client), reinterpret_cast<sockaddr*>(&server));

    int64_t new_connected_fd = 6;
    add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_E, 0);
    add_event_advance_ts(increasing_ts(), 1, PPME_SOCKET_ACCEPT_5_X, 5, new_connected_fd, scap_const_sized_buffer{st.data(), st.size()}, (uint8_t) 0, (uint32_t) 0, (uint32_t) 5);
    fdinfo = evt->get_fd_info();
    fdinfo->m_name.clear();
    fdinfo->m_name_raw.clear();
    ASSERT_EQ(get_field_as_string(evt, "fd.num"), "6");
    // no fallbacks atm
    ASSERT_EQ(get_field_as_string(evt, "anomaly.count_min_sketch.profile[1]", pl_flist), "16");
}
