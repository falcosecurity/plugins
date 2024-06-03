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

#define INIT_CONFIG                                                            \
    "{\"count_min_sketch\":\"{\"n_sketches\":3}\"}"

#define ASSERT_PLUGIN_INITIALIZATION(p_o, p_l)                                 \
    {                                                                          \
        p_o = m_inspector.register_plugin(PLUGIN_PATH);                        \
        ASSERT_TRUE(p_o.get());                                                \
        std::string err;                                                       \
        ASSERT_TRUE(p_o->init(INIT_CONFIG, err)) << "err: " << err;            \
        p_l.add_filter_check(m_inspector.new_generic_filtercheck());           \
        p_l.add_filter_check(sinsp_plugin::new_filtercheck(p_o));              \
    }
