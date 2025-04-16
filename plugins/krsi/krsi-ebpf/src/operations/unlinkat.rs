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
//! 1. `fexit:io_unlinkat` | TODO(ekoops): add syscalls support

use aya_ebpf::{cty::c_int, macros::fexit, programs::FExitContext};
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, IoKiocb, IoUnlink};

use crate::{defs, scap, shared_maps};

#[fexit]
fn io_unlinkat_x(ctx: FExitContext) -> u32 {
    try_io_unlinkat_x(ctx).unwrap_or(1)
}

fn try_io_unlinkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Unlinkat);

    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    let un: IoUnlink = req.cmd_as();

    // Parameter 1: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    auxmap.store_param(iou_ret);

    // Parameter 2: res.
    match req.cqe().res() {
        Ok(res) => auxmap.store_param(res as i64),
        Err(_) => auxmap.store_empty_param(),
    }

    // Parameter 3: dirfd.
    match un.dfd() {
        Ok(dirfd) => auxmap.store_param(scap::encode_dirfd(dirfd) as i64),
        Err(_) => auxmap.store_empty_param(),
    }

    // Parameter 4: path.
    match un.filename() {
        Ok(filename) => auxmap.store_filename_param(&filename, defs::MAX_PATH, true),
        Err(_) => auxmap.store_empty_param(),
    }

    // Parameter 5: flags.
    match un.flags() {
        Ok(flags) => auxmap.store_param(scap::encode_unlinkat_flags(flags)),
        Err(_) => auxmap.store_empty_param(),
    }

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}
