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
//! ## Kernel functions call graph (`mkdirat` syscall path)
//! ```
//! SYSCALL_DEFINE3(mkdirat, int, dfd, const char __user *, pathname, umode_t, mode)
//!     int do_mkdirat(int dfd, struct filename *name, umode_t mode)
//! ```
//!
//! ## Kernel functions call graph (`mkdir` syscall path)
//! ```
//! SYSCALL_DEFINE2(mkdir, const char __user *, pathname, umode_t, mode)
//!     int do_mkdirat(int dfd, struct filename *name, umode_t mode)
//! ```
//!
//! ## Kernel functions call graph (`io_uring` path)
//! ```
//! int io_mkdirat(struct io_kiocb *req, unsigned int issue_flags)
//!     int do_mkdirat(int dfd, struct filename *name, umode_t mode)
//! ```
//!
//! ## Extraction flow
//! 1. `fentry:io_mkdirat`
//! 2. `fexit:do_mkdirat`
//! 3. `fexit:io_mkdirat`

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
    defs,
    operations::helpers,
    scap, shared_state,
    shared_state::op_info::{MkdiratData, OpInfo},
};

#[fentry]
fn io_mkdirat_e(ctx: FEntryContext) -> u32 {
    try_io_mkdirat_e(ctx).unwrap_or(1)
}

fn try_io_mkdirat_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let op_info = OpInfo::Mkdirat(MkdiratData {});
    shared_state::op_info::insert(pid, &op_info)
}

#[fexit]
fn do_mkdirat_x(ctx: FExitContext) -> u32 {
    try_do_mkdirat_x(ctx).unwrap_or(1)
}

fn try_do_mkdirat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let is_iou = match unsafe { shared_state::op_info::get(pid) } {
        Some(OpInfo::Mkdirat(_)) => true,
        _ => false,
    };
    let is_mkdirat_sc_support_enabled =
        shared_state::is_support_enabled(FeatureFlags::SYSCALLS, OpFlags::MKDIRAT);
    if !is_iou && !is_mkdirat_sc_support_enabled {
        return Ok(0);
    }

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    helpers::preload_event_header(&mut writer, EventType::Mkdirat);

    // Parameter 1: dirfd.
    let dirfd: i32 = unsafe { ctx.arg(0) };
    writer.store_param(scap::encode_dirfd(dirfd) as i64);

    // Parameter 2: path.
    let path: Filename = wrap_arg(unsafe { ctx.arg(1) });
    writer.store_filename_param(&path, defs::MAX_PATH, true);

    // Parameter 3: mode.
    let mode: u32 = unsafe { ctx.arg(2) };
    writer.store_param(mode);

    // Parameter 4: res.
    let res: i64 = unsafe { ctx.arg(3) };
    writer.store_param(res);

    if !is_iou {
        // Parameter 5: iou_ret.
        writer.store_empty_param();
        writer.finalize_event_header();
        helpers::submit_event(auxbuf.as_bytes()?);
    }

    Ok(0)
}

#[fexit]
fn io_mkdirat_x(ctx: FExitContext) -> u32 {
    try_io_mkdirat_x(ctx).unwrap_or(1)
}

fn try_io_mkdirat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let _ = shared_state::op_info::remove(pid);

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    // Don't call writer.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:do_mkdirat`.

    // Parameter 5: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    writer.store_param(iou_ret);

    writer.finalize_event_header();
    helpers::submit_event(auxbuf.as_bytes()?);
    Ok(0)
}
