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
//! ## Kernel functions call graph (`symlinkat` syscall path)
//! ```
//! SYSCALL_DEFINE3(symlinkat, const char __user *, oldname, int, newdfd, const char __user *,
//!     newname)
//!     int do_symlinkat(struct filename *from, int newdfd, struct filename *to)
//! ```
//!
//! ## Kernel functions call graph (`symlink` syscall path)
//! ```
//! SYSCALL_DEFINE2(symlink, const char __user *, oldname, const char __user *, newname)
//!     int do_symlinkat(struct filename *from, int newdfd, struct filename *to)
//! ```
//!
//! ## Kernel functions call graph (`io_uring` path)
//! ```
//! int io_symlinkat(struct io_kiocb *req, unsigned int issue_flags)
//!     int do_symlinkat(struct filename *from, int newdfd, struct filename *to)
//! ```
//!
//! ## Extraction flow
//! 1. `fentry:io_symlinkat`
//! 2. `fexit:do_symlinkat`
//! 3. `fexit:io_symlinkat`

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

use crate::{defs, helpers, scap, shared_state};

mod maps;

#[fentry]
fn io_symlinkat_e(ctx: FEntryContext) -> u32 {
    try_io_symlinkat_e(ctx).unwrap_or(1)
}

fn try_io_symlinkat_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    const ZERO: u32 = 0;
    helpers::try_insert_map_entry(maps::get_iou_pids_map(), &pid, &ZERO)
}

#[fexit]
fn do_symlinkat_x(ctx: FExitContext) -> u32 {
    try_do_symlinkat_x(ctx).unwrap_or(1)
}

fn try_do_symlinkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let is_iou = unsafe { maps::get_iou_pids_map().get(&pid) }.is_some();
    let is_symlinkat_sc_support_enabled =
        shared_state::is_support_enabled(FeatureFlags::SYSCALLS, OpFlags::SYMLINKAT);
    if !is_iou && !is_symlinkat_sc_support_enabled {
        return Ok(0);
    }

    let auxmap = shared_state::auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Symlinkat);

    // Parameter 1: target.
    let target: Filename = wrap_arg(unsafe { ctx.arg(0) });
    auxmap.store_filename_param(&target, defs::MAX_PATH, true);

    // Parameter 2: linkdirfd.
    let linkdirfd: i32 = unsafe { ctx.arg(1) };
    auxmap.store_param(scap::encode_dirfd(linkdirfd) as i64);

    // Parameter 3: linkpath.
    let linkpath: Filename = wrap_arg(unsafe { ctx.arg(2) });
    auxmap.store_filename_param(&linkpath, defs::MAX_PATH, true);

    // Parameter 4: res.
    let res: i64 = unsafe { ctx.arg(3) };
    auxmap.store_param(res);

    if !is_iou {
        // Parameter 5: iou_ret.
        auxmap.store_empty_param();
        auxmap.finalize_event_header();
        auxmap.submit_event();
    }

    Ok(0)
}

#[fexit]
fn io_symlinkat_x(ctx: FExitContext) -> u32 {
    try_io_symlinkat_x(ctx).unwrap_or(1)
}

fn try_io_symlinkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let _ = helpers::try_remove_map_entry(maps::get_iou_pids_map(), &pid);

    let auxmap = shared_state::auxiliary_map().ok_or(1)?;
    // Don't call auxmap.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:do_symlinkat`.

    // Parameter 5: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    auxmap.store_param(iou_ret);

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}
