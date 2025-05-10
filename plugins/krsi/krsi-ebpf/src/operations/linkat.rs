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
//! ## Kernel functions call graph (`linkat` syscall path)
//! ```
//! SYSCALL_DEFINE5(linkat, int, olddfd, const char __user *, oldname, int, newdfd,
//!     const char __user *, newname, int, flags)
//!     int do_linkat(int olddfd, struct filename *old, int newdfd, struct filename *new, int flags)
//! ```
//!
//! ## Kernel functions call graph (`link` syscall path)
//! ```
//! SYSCALL_DEFINE2(link, const char __user *, oldname, const char __user *, newname)
//!     int do_linkat(int olddfd, struct filename *old, int newdfd, struct filename *new, int flags)
//! ```
//!
//! ## Kernel functions call graph (`io_linkat` path)
//! ```
//! int io_linkat(struct io_kiocb *req, unsigned int issue_flags)
//!    int do_linkat(int olddfd, struct filename *old, int newdfd, struct filename *new, int flags)
//! ```
//!
//! ## Extraction flow
//! 1. `fentry:io_linkat`
//! 2. `fexit:do_linkat`
//! 3. `fexit:io_linkat`

use aya_ebpf::{
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
    EbpfContext,
};
use krsi_common::{
    flags::{FeatureFlags, OpFlags},
    EventType,
};
use krsi_ebpf_core::{wrap_arg, Filename};

use crate::{
    defs, scap, shared_state,
    shared_state::op_info::{LinkatData, OpInfo},
    submit_event,
};

#[fentry]
fn io_linkat_e(ctx: FEntryContext) -> u32 {
    try_io_linkat_e(ctx).unwrap_or(1)
}

fn try_io_linkat_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let op_info = OpInfo::Linkat(LinkatData {});
    shared_state::op_info::insert(pid, &op_info)
}

#[fexit]
fn do_linkat_x(ctx: FExitContext) -> u32 {
    try_do_linkat_x(ctx).unwrap_or(1)
}

fn try_do_linkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let is_iou = match unsafe { shared_state::op_info::get(pid) } {
        Some(OpInfo::Linkat(_)) => true,
        _ => false,
    };
    let is_linkat_sc_support_enabled =
        shared_state::is_support_enabled(FeatureFlags::SYSCALLS, OpFlags::LINKAT);
    if !is_iou && !is_linkat_sc_support_enabled {
        return Ok(0);
    }

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    writer.preload_event_header(EventType::Linkat);

    // Parameter 1: olddirfd.
    let olddirfd: i32 = unsafe { ctx.arg(0) };
    writer.store_param(scap::encode_dirfd(olddirfd) as i64);

    // Parameter 2: oldpath.
    let oldpath: Filename = wrap_arg(unsafe { ctx.arg(1) });
    writer.store_filename_param(&oldpath, defs::MAX_PATH, true);

    // Parameter 3: newdirfd.
    let olddirfd: i32 = unsafe { ctx.arg(2) };
    writer.store_param(scap::encode_dirfd(olddirfd) as i64);

    // Parameter 4: newpath.
    let newpath: Filename = wrap_arg(unsafe { ctx.arg(3) });
    writer.store_filename_param(&newpath, defs::MAX_PATH, true);

    // Parameter 5: flags.
    let flags: i32 = unsafe { ctx.arg(4) };
    writer.store_param(scap::encode_linkat_flags(flags) as u32);

    // Parameter 6: res.
    let res: i64 = unsafe { ctx.arg(5) };
    writer.store_param(res);

    if !is_iou {
        // Parameter 7: iou_ret.
        writer.store_empty_param();
        writer.finalize_event_header();
        submit_event(auxbuf.as_bytes()?);
    }

    Ok(0)
}

#[fexit]
fn io_linkat_x(ctx: FExitContext) -> u32 {
    try_io_linkat_x(ctx).unwrap_or(1)
}

fn try_io_linkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let _ = shared_state::op_info::remove(pid);

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    // Don't call writer.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:do_linkat`.

    // Parameter 7: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    writer.store_param(iou_ret);

    writer.finalize_event_header();
    submit_event(auxbuf.as_bytes()?);
    Ok(0)
}
