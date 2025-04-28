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

#[derive(Clone, Copy)]
pub struct Info {
    pub file_descriptor: FileDescriptor,
    pub is_iou: bool,
    pub socktuple_len: u16,
}

impl Info {
    pub fn new(file_descriptor: FileDescriptor, is_iou: bool) -> Self {
        Self {
            file_descriptor,
            is_iou,
            socktuple_len: 0,
        }
    }
}

#[map]
static CONN_INFO: HashMap<u32, Info> = HashMap::with_max_entries(32768, 0);

pub fn get_info_map() -> &'static HashMap<u32, Info> {
    &CONN_INFO
}
