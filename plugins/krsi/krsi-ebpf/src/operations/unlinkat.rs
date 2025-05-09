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
//! ## Kernel functions call graph (`unlinkat` syscall path)
//! ```
//! SYSCALL_DEFINE3(unlinkat, int, dfd, const char __user *, pathname, int, flag)
//!     if (...) int do_rmdir(int dfd, struct filename *name)
//!     else int do_unlinkat(int dfd, struct filename *name)
//! ```
//!
//! ## Kernel functions call graph (`unlink` syscall path)
//! ```
//! SYSCALL_DEFINE1(unlink, const char __user *, pathname)
//!     int do_unlinkat(int dfd, struct filename *name)
//! ```
//!
//! ## Kernel functions call graph (`io_uring` path)
//! ```
//! int io_unlinkat(struct io_kiocb *req, unsigned int issue_flags)
//!     if (...) int do_rmdir(int dfd, struct filename *name)
//!     else int do_unlinkat(int dfd, struct filename *name)
//! ```
//!
//! ## Extraction flow
//! 1. `fentry:io_unlinkat` | `fentry:__x64_sys_unlink` | `fentry:__x64_sys_unlinkat`
//! 2. `fexit:do_unlinkat` | `fexit:do_rmdir`
//! 3. `fexit:io_unlinkat` | `fexit:__x64_sys_unlink` | `fexit:__x64_sys_unlinkat`

use aya_ebpf::{
    bindings::pt_regs,
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
    EbpfContext, PtRegs,
};
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, Filename, IoKiocb, IoUnlink};

use crate::{
    defs, scap, shared_state,
    shared_state::op_info::{OpInfo, UnlinkatData},
};

#[fentry]
fn io_unlinkat_e(ctx: FEntryContext) -> u32 {
    try_io_unlinkat_e(ctx).unwrap_or(1)
}

fn try_io_unlinkat_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    let un: IoUnlink = req.cmd_as();
    let op_info = OpInfo::Unlinkat(UnlinkatData {
        is_iou: true,
        flags: un.flags().ok(),
    });
    shared_state::op_info::insert(pid, &op_info)
}

#[fentry]
#[allow(non_snake_case)]
fn __x64_sys_unlink_e(ctx: FEntryContext) -> u32 {
    try___x64_sys_unlink_e(ctx).unwrap_or(1)
}

#[allow(non_snake_case)]
fn try___x64_sys_unlink_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let op_info = OpInfo::Unlinkat(UnlinkatData {
        is_iou: false,
        flags: Some(0),
    });
    shared_state::op_info::insert(pid, &op_info)
}

#[fentry]
#[allow(non_snake_case)]
fn __x64_sys_unlinkat_e(ctx: FEntryContext) -> u32 {
    try___x64_sys_unlinkat_e(ctx).unwrap_or(1)
}

#[allow(non_snake_case)]
fn try___x64_sys_unlinkat_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let pt_regs = PtRegs::new(unsafe { ctx.arg::<*const pt_regs>(0) } as *mut _);
    let op_info = OpInfo::Unlinkat(UnlinkatData {
        is_iou: false,
        flags: pt_regs.arg(2),
    });
    shared_state::op_info::insert(pid, &op_info)
}

#[fexit]
fn do_unlinkat_x(ctx: FExitContext) -> u32 {
    try_do_unlinkat_x(ctx).unwrap_or(1)
}

fn try_do_unlinkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(OpInfo::Unlinkat(op_data)) = (unsafe { shared_state::op_info::get(pid) }) else {
        return Ok(0);
    };

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    auxbuf.preload_event_header(EventType::Unlinkat);

    // Parameter 1: dirfd.
    let dirfd: i32 = unsafe { ctx.arg(0) };
    auxbuf.store_param(scap::encode_dirfd(dirfd) as i64);

    // Parameter 2: path.
    let path: Filename = wrap_arg(unsafe { ctx.arg(1) });
    auxbuf.store_filename_param(&path, defs::MAX_PATH, true);

    // Parameter 3: flags.
    match op_data.flags {
        Some(flags) => auxbuf.store_param(scap::encode_unlinkat_flags(flags)),
        None => auxbuf.store_empty_param(),
    }

    // parameter 4: res.
    let res: i64 = unsafe { ctx.arg(2) };
    auxbuf.store_param(res);

    if !op_data.is_iou {
        // Parameter 5: iou_ret.
        auxbuf.store_empty_param();
        auxbuf.finalize_event_header();
        auxbuf.submit_event();
    }

    Ok(0)
}

#[fexit]
fn do_rmdir_x(ctx: FExitContext) -> u32 {
    // Share the same extraction code with do_unlinkat.
    try_do_unlinkat_x(ctx).unwrap_or(1)
}

#[fexit]
#[allow(non_snake_case)]
fn __x64_sys_unlinkat_x(ctx: FExitContext) -> u32 {
    try___x64_sys_unlinkat_x(ctx).unwrap_or(1)
}

#[allow(non_snake_case)]
fn try___x64_sys_unlinkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    shared_state::op_info::remove(pid)
}

#[fexit]
#[allow(non_snake_case)]
fn __x64_sys_unlink_x(ctx: FExitContext) -> u32 {
    // Share the same code with x64_sys_unlinkat.
    try___x64_sys_unlinkat_x(ctx).unwrap_or(1)
}

#[fexit]
fn io_unlinkat_x(ctx: FExitContext) -> u32 {
    try_io_unlinkat_x(ctx).unwrap_or(1)
}

fn try_io_unlinkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let _ = shared_state::op_info::remove(pid);

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    // Don't call auxbuf.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:do_unlinkat` or `fexit:do_rmdir`.

    // Parameter 5: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    auxbuf.store_param(iou_ret);

    auxbuf.finalize_event_header();
    auxbuf.submit_event();
    Ok(0)
}
