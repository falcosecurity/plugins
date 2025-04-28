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

use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct FeatureFlags: u8 {
        const NONE = 0;
        const IO_URING = 1 << 0;
        const SYSCALLS = 1 << 1;
    }
}

bitflags! {
    #[derive(Clone, Copy, Debug)]
    pub struct OpFlags: u64 {
        const OPEN = 1 << 0;
        const CONNECT = 1 << 1;
        const SOCKET = 1 << 2;
        const SYMLINKAT = 1 << 3;
        const LINKAT = 1 << 4;
        const UNLINKAT = 1 << 5;
        const MKDIRAT = 1 << 6;
        const RENAMEAT = 1 << 7;
        const BIND = 1 << 8;
    }
}
