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
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, Filename};

use crate::{defs, helpers, scap, shared_maps};

mod maps;

#[fentry]
fn io_mkdirat_e(ctx: FEntryContext) -> u32 {
    try_io_mkdirat_e(ctx).unwrap_or(1)
}

fn try_io_mkdirat_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    const ZERO: u32 = 0;
    helpers::try_insert_map_entry(maps::get_iou_pids_map(), &pid, &ZERO)
}

#[fexit]
fn do_mkdirat_x(ctx: FExitContext) -> u32 {
    try_do_mkdirat_x(ctx).unwrap_or(1)
}

fn try_do_mkdirat_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Mkdirat);

    // Parameter 1: dirfd.
    let dirfd: i32 = unsafe { ctx.arg(0) };
    auxmap.store_param(scap::encode_dirfd(dirfd) as i64);

    // Parameter 2: path.
    let path: Filename = wrap_arg(unsafe { ctx.arg(1) });
    auxmap.store_filename_param(&path, defs::MAX_PATH, true);

    // Parameter 3: mode.
    let mode: u32 = unsafe { ctx.arg(2) };
    auxmap.store_param(mode);

    // Parameter 4: res.
    let res: i64 = unsafe { ctx.arg(3) };
    auxmap.store_param(res);

    let pid = ctx.pid();
    // Not having an entry in the map means that this is not an io_uring operation. In case of an
    // io_uring operation, don't submit the event but let `fexit:io_mkdirat` handle it.
    if unsafe { maps::get_iou_pids_map().get(&pid) }.is_none() {
        // Parameter 5: iou_ret
        auxmap.store_empty_param();
        auxmap.finalize_event_header();
        auxmap.submit_event();
    }

    Ok(0)
}

#[fexit]
fn io_mkdirat_x(ctx: FExitContext) -> u32 {
    try_io_mkdirat_x(ctx).unwrap_or(1)
}

fn try_io_mkdirat_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let _ = helpers::try_remove_map_entry(maps::get_iou_pids_map(), &pid);

    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    // Don't call auxmap.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:do_mkdirat`.

    // Parameter 5: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    auxmap.store_param(iou_ret);

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}
