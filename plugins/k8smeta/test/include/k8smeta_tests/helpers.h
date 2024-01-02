
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
#pragma once

// We can modify the log verbosity here.
#define INIT_CONFIG                                                            \
    "{\"collectorHostname\":\"localhost\",\"collectorPort\": "                 \
    "45000,\"nodeName\":\"control-plane\",\"verbosity\":"                      \
    "\"info\"}"

#define ASSERT_STRING_SETS(a, b)                                               \
    {                                                                          \
        auto a1 = a;                                                           \
        auto b1 = b;                                                           \
        EXPECT_EQ(a1.size(), b1.size());                                       \
        ASSERT_EQ(std::set<std::string>(a1.begin(), a1.end()),                 \
                  std::set<std::string>(b1.begin(), b1.end()));                \
    }

#define ASSERT_PPME_SETS(a, b)                                                 \
    {                                                                          \
        auto a1 = a;                                                           \
        auto b1 = b;                                                           \
        EXPECT_EQ(a1.size(), b1.size());                                       \
        ASSERT_EQ(std::set<ppm_event_code>(a1.begin(), a1.end()),              \
                  std::set<ppm_event_code>(b1.begin(), b1.end()));             \
    }

#define ASSERT_PLUGIN_INITIALIZATION(p_o, p_l)                                 \
    {                                                                          \
        p_o = m_inspector.register_plugin(PLUGIN_PATH);                        \
        ASSERT_TRUE(p_o.get());                                                \
        std::string err;                                                       \
        ASSERT_TRUE(p_o->init(INIT_CONFIG, err)) << "err: " << err;            \
        p_l.add_filter_check(m_inspector.new_generic_filtercheck());           \
        p_l.add_filter_check(sinsp_plugin::new_filtercheck(p_o));              \
    }

#define GENERATE_EXECVE_EVENT_FOR_INIT(_pod_uid)                               \
    evt = generate_execve_enter_and_exit_event(                                \
            0, INIT_TID, INIT_TID, INIT_PID, INIT_PTID, "init", "init",        \
            "/lib/systemd/systemd",                                            \
            {"cpuset=/kubepods/besteffort/pod" + _pod_uid +                    \
             "/691e0ffb65010b2b611f3a15b7f76c48466192e673e156f38bd2f8e25acd6b" \
             "bc"});                                                           \
    ASSERT_EQ(evt->get_type(), PPME_SYSCALL_EXECVE_19_X);
