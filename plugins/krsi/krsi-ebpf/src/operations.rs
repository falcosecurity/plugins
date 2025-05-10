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

mod helpers {
    use aya_ebpf::{
        bindings::BPF_RB_FORCE_WAKEUP,
        helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns},
    };
    use krsi_common::EventType;

    use crate::{auxbuf::Writer, shared_state, MAX_EVENT_LEN};

    pub fn preload_event_header(writer: &mut Writer, event_type: EventType) {
        let ts = shared_state::boot_time() + unsafe { bpf_ktime_get_boot_ns() };
        let tgid_pid = bpf_get_current_pid_tgid();
        let nparams = get_event_num_params(event_type) as u32;
        writer.preload_event_header(ts, tgid_pid, event_type, nparams);
    }

    fn get_event_num_params(event_type: EventType) -> u8 {
        match event_type.try_into() {
            // TODO(ekoops): try to generate the following numbers automatically.
            Ok(EventType::Open) => 8,
            Ok(EventType::Connect) => 5,
            Ok(EventType::Socket) => 6,
            Ok(EventType::Symlinkat) => 5,
            Ok(EventType::Linkat) => 7,
            Ok(EventType::Unlinkat) => 5,
            Ok(EventType::Mkdirat) => 5,
            Ok(EventType::Renameat) => 7,
            Ok(EventType::Bind) => 5,
            _ => 0,
        }
    }

    pub fn submit_event(event: &[u8]) {
        if event.len() > MAX_EVENT_LEN {
            return;
        }
        let _ = shared_state::events_ringbuf().output(event, BPF_RB_FORCE_WAKEUP as u64);
    }
}
