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

#define INIT_CONFIG "{\"count_min_sketch\":{\"enabled\":true,\"n_sketches\":3,\"gamma_eps\":[[0.001,0.0001],[0.001,0.0001],[0.001,0.0001]],\"behavior_profiles\":[\
{\"fields\":\"%container.id %proc.name %proc.pname %proc.exepath %proc.pexepath %proc.tty %proc.vpid %proc.pvid]\",\
\"event_codes\":[293,331]},\
{\"fields\":\"%proc.pid %fd.num %fd.name %fd.directory %fd.filename %fd.dev %fd.ino %fd.nameraw %fs.path.name %fs.path.nameraw\",\
\"event_codes\":[3,307,327,23]},\
{\"fields\":\"%container.id %proc.cmdline %proc.name %proc.aname[0] %proc.aname[1] %proc.aname[2] %proc.aname[3] %proc.aname[4] %proc.aname[5] %proc.aname[6] %proc.aname[7] %proc.pid %proc.apid[0] %proc.apid[1] %proc.apid[2] %proc.apid[3] %proc.apid[4] %proc.apid[5] %proc.apid[6] %proc.apid[7] %proc.exepath %proc.aexepath[0] %proc.aexepath[1] %proc.aexepath[2] %proc.aexepath[3] %proc.aexepath[4] %proc.aexepath[5] %proc.aexepath[6] %proc.aexepath[7] %proc.vpgid %proc.vpgid.name %proc.sid %proc.sname\",\
\"event_codes\":[293,331]}]}}"

#define ASSERT_PLUGIN_INITIALIZATION(p_o, p_l)                                 \
    {                                                                          \
        p_o = m_inspector.register_plugin(PLUGIN_PATH);                        \
        ASSERT_TRUE(p_o.get());                                                \
        std::string err;                                                       \
        ASSERT_TRUE(p_o->init(INIT_CONFIG, err)) << "err: " << err;            \
        p_l.add_filter_check(m_inspector.new_generic_filtercheck());           \
        p_l.add_filter_check(sinsp_plugin::new_filtercheck(p_o));              \
    }

#define DEFAULT_IPV4_CLIENT_STRING "172.40.111.222"
#define DEFAULT_IPV6_CLIENT_STRING "::1"
#define DEFAULT_CLIENT_PORT_STRING "54321"
#define DEFAULT_CLIENT_PORT 54321

#define DEFAULT_IPV4_SERVER_STRING "142.251.111.147"
#define DEFAULT_IPV6_SERVER_STRING "2001:4860:4860::8888"
#define DEFAULT_SERVER_PORT_STRING "443"
#define DEFAULT_SERVER_PORT 443

#define DEFAULT_IPV4_FDNAME "172.40.111.222:54321->142.251.111.147:443"
#define DEFAULT_IPV6_FDNAME "::1:54321->2001:4860:4860::8888:443"

#define DEFAULT_IP_STRING_SIZE 100
