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
//! ## Kernel functions call graph (`socket` and `socketcall` syscalls path)
//! ```
//! int __sys_socket(int family, int type, int protocol)
//!     static int sock_map_fd(struct socket *sock, int flags)
//!         struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
//!         void fd_install(unsigned int fd, struct file *file)
//! ```
//!
//! ## Kernel functions call graph (`io_uring` path)
//! ```
//! io_socket(struct io_kiocb *req, unsigned int issue_flags)
//!     struct file *__sys_socket_file(int family, int type, int protocol)
//!         static struct socket *__sys_socket_create(int family, int type, int protocol)
//!         struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
//!     if (...) void fd_install(unsigned int fd, struct file *file)
//!     else int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
//!         struct file *file, unsigned int file_slot)
//! ```
//!
//! ## Extraction flow
//! 1. `fexit:__sys_socket` | `fexit:io_socket`

use aya_ebpf::{cty::c_int, macros::fexit, programs::FExitContext};
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, IoKiocb, IoSocket};

use crate::{defs, shared_state, submit_event, FileDescriptor};

#[fexit]
fn io_socket_x(ctx: FExitContext) -> u32 {
    try_io_socket_x(ctx).unwrap_or(1)
}

fn try_io_socket_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    auxbuf.preload_event_header(EventType::Socket);

    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    let sock = req.cmd_as::<IoSocket>();

    let iou_ret: i64 = unsafe { ctx.arg(2) };

    // Parameter 1: iou_ret.
    auxbuf.store_param(iou_ret);

    // Parameter 2: fd.
    // Parameter 3: file_index.
    match extract_file_descriptor(&req, &sock, iou_ret) {
        Ok(Some(file_descriptor)) => auxbuf.store_file_descriptor_param(file_descriptor),
        _ => {
            auxbuf.store_empty_param();
            auxbuf.store_empty_param();
        }
    }

    // Parameter 4: domain.
    match sock.domain() {
        Ok(sock_domain) => auxbuf.store_param(sock_domain as u32),
        Err(_) => auxbuf.store_empty_param(),
    };

    // Parameter 5: type.
    match sock.r#type() {
        Ok(sock_type) => auxbuf.store_param(sock_type as u32),
        Err(_) => auxbuf.store_empty_param(),
    };

    // Parameter 6: proto.
    match sock.protocol() {
        Ok(sock_proto) => auxbuf.store_param(sock_proto as u32),
        Err(_) => auxbuf.store_empty_param(),
    };

    auxbuf.finalize_event_header();
    submit_event(auxbuf.as_bytes()?);
    Ok(0)
}

fn extract_file_descriptor(
    req: &IoKiocb,
    sock: &IoSocket,
    iou_ret: i64,
) -> Result<Option<FileDescriptor>, i64> {
    if iou_ret != defs::IOU_OK {
        return Ok(None);
    }
    let cqe_res = req.cqe().res()?;
    let file_slot = sock.file_slot()?;
    let fixed = file_slot != 0;
    Ok(Some(if !fixed {
        FileDescriptor::Fd(cqe_res)
    } else if cqe_res < 0 || file_slot == defs::IORING_FILE_INDEX_ALLOC {
        FileDescriptor::FileIndex(cqe_res)
    } else {
        FileDescriptor::FileIndex((file_slot - 1) as i32)
    }))
}

#[fexit]
#[allow(non_snake_case)]
fn __sys_socket_x(ctx: FExitContext) -> u32 {
    try___sys_socket_x(ctx).unwrap_or(1)
}

#[allow(non_snake_case)]
fn try___sys_socket_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    auxbuf.preload_event_header(EventType::Socket);

    // Parameter 1: iou_ret.
    auxbuf.store_empty_param();

    // Parameter 2: fd.
    let ret: c_int = unsafe { ctx.arg(3) };
    auxbuf.store_param(ret as i64);

    // Parameter 3: file_index.
    auxbuf.store_empty_param();

    // Parameter 4: domain.
    let sock_domain: c_int = unsafe { ctx.arg(0) };
    auxbuf.store_param(sock_domain as u32);

    // Parameter 5: type.
    let sock_type: c_int = unsafe { ctx.arg(1) };
    auxbuf.store_param(sock_type as u32);

    // Parameter 6: proto.
    let sock_proto: c_int = unsafe { ctx.arg(2) };
    auxbuf.store_param(sock_proto as u32);

    auxbuf.finalize_event_header();
    submit_event(auxbuf.as_bytes()?);
    Ok(0)
}
