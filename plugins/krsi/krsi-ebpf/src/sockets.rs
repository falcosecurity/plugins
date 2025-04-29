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

use aya_ebpf::helpers::{bpf_probe_read_kernel_buf, bpf_probe_read_user_buf};
use krsi_ebpf_core::{ffi::sockaddr_un, SockaddrUn, UnixSock, Wrap};

use crate::defs;

/// Equivalent to `*path = sk->addr->name[0].sun_path`.
pub fn unix_sock_addr_path_into(
    sk: &UnixSock,
    path: &mut [u8; defs::UNIX_PATH_MAX],
) -> Result<(), i64> {
    let addr = sk.addr()?;
    let len = addr.len()?;
    if len == 0 {
        return Ok(());
    }

    let first_sockaddr = SockaddrUn::wrap(addr.name().cast::<sockaddr_un>());
    let sun_path = first_sockaddr.sun_path();
    unsafe { bpf_probe_read_kernel_buf(sun_path.cast(), path) }
}

/// Equivalent to `*path = sockaddr->sun_path`.
pub fn sockaddr_un_path_into(
    sockaddr: &SockaddrUn,
    is_kern_mem: bool,
    path: &mut [u8; defs::UNIX_PATH_MAX],
) -> Result<(), i64> {
    let sun_path = sockaddr.sun_path();
    if is_kern_mem {
        unsafe { bpf_probe_read_kernel_buf(sun_path.cast(), path) }
    } else {
        unsafe { bpf_probe_read_user_buf(sun_path.cast(), path) }
    }
}
