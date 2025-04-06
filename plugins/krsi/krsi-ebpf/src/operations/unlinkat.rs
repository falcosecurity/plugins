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

use crate::{defs, files, iouring, scap, shared_maps, vmlinux};

#[fexit]
fn io_unlinkat_x(ctx: FExitContext) -> u32 {
    try_io_unlinkat_x(ctx).unwrap_or(1)
}

fn try_io_unlinkat_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Unlinkat);

    let req: *const vmlinux::io_kiocb = unsafe { ctx.arg(0) };
    let un: *const vmlinux::io_unlink = iouring::extract::io_kiocb_cmd_ptr(req);

    // Parameter 1: iou_ret.
    let iou_ret: c_int = unsafe { ctx.arg(2) };
    auxmap.store_param(iou_ret as i64);

    // Parameter 2: res.
    match iouring::extract::io_kiocb_cqe_res(req) {
        Ok(res) => auxmap.store_param(res as i64),
        Err(_) => auxmap.store_empty_param(),
    }

    // Parameter 3: dirfd.
    match iouring::extract::io_unlink_dfd(un) {
        Ok(dirfd) => auxmap.store_param(scap::encode_dirfd(dirfd) as i64),
        Err(_) => auxmap.store_empty_param(),
    }

    // Parameter 4: path.
    let result = iouring::extract::io_unlink_filename(un)
        .and_then(files::extract::filename_name)
        .and_then(|name| unsafe { auxmap.store_charbuf_param(name, defs::MAX_PATH, true) });
    if result.is_err() {
        auxmap.store_empty_param();
    }

    // Parameter 5: flags.
    match iouring::extract::io_unlink_flags(un) {
        Ok(flags) => auxmap.store_param(scap::encode_unlinkat_flags(flags)),
        Err(_) => auxmap.store_empty_param(),
    }

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}
