// SPDX-License-Identifier: Apache-2.0
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

use aya_ebpf::{macros::map, maps::HashMap};

use crate::FileDescriptor;

#[map]
static BIND_FDS: HashMap<u32, FileDescriptor> = HashMap::with_max_entries(32768, 0);

pub fn get_file_descriptors_map() -> &'static HashMap<u32, FileDescriptor> {
    &BIND_FDS
}
