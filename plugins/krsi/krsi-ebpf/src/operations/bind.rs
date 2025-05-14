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

//! # Data extraction
//!
//! ## Kernel functions call graph (`bind` syscall path)
//! ```
//! SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
//!     int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
//!         int __sys_bind_socket(struct socket *sock, struct sockaddr_storage *address,
//!             int addrlen)
//! ```
//!
//! ## Kernel functions call graph (`socketcall` syscall path)
//! ```
//! SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
//!     int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
//!         int __sys_bind_socket(struct socket *sock, struct sockaddr_storage *address,
//!             int addrlen)
//! ```
//!
//! ## Kernel function call graph (`io_uring` path)
//! ```
//! int io_bind(struct io_kiocb *req, unsigned int issue_flags)
//!     int __sys_bind_socket(struct socket *sock, struct sockaddr_storage *address, int addrlen)
//! ```
//!
//! ## Extraction flow
//! 1. `fentry:io_bind`
//! 2. `fexit:io_bind` | `fexit:__sys_bind`

use aya_ebpf::{
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
    EbpfContext,
};
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, IoAsyncMsghdr, IoKiocb, Sockaddr};

use crate::{
    iouring,
    operations::{helpers, writer_helpers},
    shared_state,
    shared_state::op_info::{BindData, OpInfo},
    FileDescriptor,
};

#[fentry]
fn io_bind_e(ctx: FEntryContext) -> u32 {
    try_io_bind_e(ctx).unwrap_or(1)
}

fn try_io_bind_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    let file_descriptor = iouring::io_kiocb_cqe_file_descriptor(&req)?;
    let op_info = OpInfo::Bind(BindData { file_descriptor });
    shared_state::op_info::insert(pid, &op_info)
}

#[fexit]
fn io_bind_x(ctx: FExitContext) -> u32 {
    try_io_bind_x(ctx).unwrap_or(1)
}

fn try_io_bind_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(OpInfo::Bind(BindData { file_descriptor })) =
        (unsafe { shared_state::op_info::get(pid) })
    else {
        return Err(1);
    };

    let _ = shared_state::op_info::remove(pid);

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    writer_helpers::preload_event_header(&mut writer, EventType::Bind);

    // Parameter 1: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    writer.store_param(iou_ret);

    // Parameter 2: res.
    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    match iouring::io_kiocb_cqe_res(&req, iou_ret) {
        Ok(Some(cqe_res)) => writer.store_param(cqe_res as i64),
        _ => writer.store_empty_param(),
    }

    // Parameter 3: addr.
    match req.async_data_as::<IoAsyncMsghdr>() {
        Ok(io) => writer_helpers::store_sockaddr_param(&mut writer, &io.addr(), true),
        Err(_) => writer.store_empty_param(),
    };

    // Parameter 4: fd.
    // Parameter 5: file_index.
    writer_helpers::store_file_descriptor_param(&mut writer, *file_descriptor);

    writer.finalize_event_header();
    helpers::submit_event(auxbuf.as_bytes()?);
    Ok(0)
}

#[fexit]
#[allow(non_snake_case)]
fn __sys_bind_x(ctx: FExitContext) -> u32 {
    try___sys_bind_x(ctx).unwrap_or(1)
}

#[allow(non_snake_case)]
fn try___sys_bind_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    writer_helpers::preload_event_header(&mut writer, EventType::Bind);

    // Parameter 1: iou_ret.
    writer.store_empty_param();

    // Parameter 2: res.
    let res: i64 = unsafe { ctx.arg(3) };
    writer.store_param(res);

    // Parameter 3: addr.
    let sockaddr: Sockaddr = wrap_arg(unsafe { ctx.arg(1) });
    writer_helpers::store_sockaddr_param(&mut writer, &sockaddr, false);

    // Parameter 4: fd.
    // Parameter 5: file_index.
    let fd = unsafe { ctx.arg(0) };
    let file_descriptor = FileDescriptor::Fd(fd);
    writer_helpers::store_file_descriptor_param(&mut writer, file_descriptor);

    writer.finalize_event_header();
    helpers::submit_event(auxbuf.as_bytes()?);
    Ok(0)
}
