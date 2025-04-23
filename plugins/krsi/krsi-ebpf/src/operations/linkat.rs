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

use crate::{defs, helpers, scap, shared_maps};

mod maps;

#[fentry]
fn io_linkat_e(ctx: FEntryContext) -> u32 {
    try_io_linkat_e(ctx).unwrap_or(1)
}

fn try_io_linkat_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    const ZERO: u32 = 0;
    helpers::try_insert_map_entry(maps::get_iou_pids_map(), &pid, &ZERO)
}

#[fexit]
fn do_linkat_x(ctx: FExitContext) -> u32 {
    try_do_linkat_x(ctx).unwrap_or(1)
}

fn try_do_linkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let is_iou = unsafe { maps::get_iou_pids_map().get(&pid) }.is_some();
    let is_linkat_sc_support_enabled =
        shared_maps::is_support_enabled(FeatureFlags::SYSCALLS, OpFlags::LINKAT);
    if !is_iou && !is_linkat_sc_support_enabled {
        return Ok(0);
    }

    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Linkat);

    // Parameter 1: olddirfd.
    let olddirfd: i32 = unsafe { ctx.arg(0) };
    auxmap.store_param(scap::encode_dirfd(olddirfd) as i64);

    // Parameter 2: oldpath.
    let oldpath: Filename = wrap_arg(unsafe { ctx.arg(1) });
    auxmap.store_filename_param(&oldpath, defs::MAX_PATH, true);

    // Parameter 3: newdirfd.
    let olddirfd: i32 = unsafe { ctx.arg(2) };
    auxmap.store_param(scap::encode_dirfd(olddirfd) as i64);

    // Parameter 4: newpath.
    let newpath: Filename = wrap_arg(unsafe { ctx.arg(3) });
    auxmap.store_filename_param(&newpath, defs::MAX_PATH, true);

    // Parameter 5: flags.
    let flags: i32 = unsafe { ctx.arg(4) };
    auxmap.store_param(scap::encode_linkat_flags(flags) as u32);

    // Parameter 6: res.
    let res: i64 = unsafe { ctx.arg(5) };
    auxmap.store_param(res);

    if !is_iou {
        // Parameter 7: iou_ret.
        auxmap.store_empty_param();
        auxmap.finalize_event_header();
        auxmap.submit_event();
    }

    Ok(0)
}

#[fexit]
fn io_linkat_x(ctx: FExitContext) -> u32 {
    try_io_linkat_x(ctx).unwrap_or(1)
}

fn try_io_linkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let _ = helpers::try_remove_map_entry(maps::get_iou_pids_map(), &pid);

    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    // Don't call auxmap.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:do_linkat`.

    // Parameter 7: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    auxmap.store_param(iou_ret);

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}
