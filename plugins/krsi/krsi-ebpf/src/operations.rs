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

pub mod bind;
pub mod connect;
pub mod linkat;
pub mod mkdirat;
pub mod open;
pub mod renameat;
pub mod socket;
pub mod symlinkat;
pub mod unlinkat;
pub mod writer_helpers;
pub mod helpers {
    use aya_ebpf::bindings::BPF_RB_FORCE_WAKEUP;

    use crate::shared_state;

    pub fn submit_event(event: &[u8]) {
        if event.len() > crate::MAX_EVENT_LEN {
            return;
        }
        let _ = shared_state::events_ringbuf().output(event, BPF_RB_FORCE_WAKEUP as u64);
    }
}
