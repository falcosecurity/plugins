//! # Data extraction
//!
//! ## Kernel functions call graph (`connect` and `socketcall` syscalls path)
//! ```
//! int __sys_connect(int fd, struct sockaddr __user *uservaddr, int addrlen)
//!     int __sys_connect_file(struct file *file, struct sockaddr_storage *address, int addrlen,
//!         int file_flags)
//! ```
//!
//! ## Kernel function call graph (`io_uring` path)
//! ```
//! int io_connect(struct io_kiocb *req, unsigned int issue_flags)
//!     int __sys_connect_file(struct file *file, struct sockaddr_storage *address, int addrlen,
//!         int file_flags)
//! ```
//!
//! ## Extraction flow
//! 1. `fentry:io_connect` | `fentry:__sys_connect`
//! 2. `fexit:__sys_connect_file`
//! 3. `fexit:io_connect` | `fexit:__sys_connect`

use core::ptr::null_mut;

use aya_ebpf::{
    cty::c_int,
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
    EbpfContext,
};
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, File, IoKiocb, Sockaddr, Socket, Wrap};

use crate::{defs, helpers, iouring, operations::connect::maps::Info, shared_maps, FileDescriptor};

mod maps;

#[fentry]
fn io_connect_e(ctx: FEntryContext) -> u32 {
    try_io_connect_e(ctx).unwrap_or(1)
}

fn try_io_connect_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    let file_descriptor = iouring::io_kiocb_cqe_file_descriptor(&req)?;
    const IS_IOU: bool = true;
    let info = Info::new(file_descriptor, IS_IOU);
    helpers::try_insert_map_entry(maps::get_info_map(), &pid, &info)
}

#[fentry]
#[allow(non_snake_case)]
fn __sys_connect_e(ctx: FEntryContext) -> u32 {
    try___sys_connect_e(ctx).unwrap_or(1)
}

#[allow(non_snake_case)]
fn try___sys_connect_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let fd: c_int = unsafe { ctx.arg(0) };
    const IS_IOU: bool = false;
    let info = Info::new(FileDescriptor::Fd(fd as i32), IS_IOU);
    helpers::try_insert_map_entry(maps::get_info_map(), &pid, &info)
}

#[fexit]
#[allow(non_snake_case)]
fn __sys_connect_file_x(ctx: FExitContext) -> u32 {
    try___sys_connect_file_x(ctx).unwrap_or(1)
}

#[allow(non_snake_case)]
fn try___sys_connect_file_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(info) = maps::get_info_map().get_ptr_mut(&pid) else {
        return Ok(0);
    };

    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Connect);

    let ret: c_int = unsafe { ctx.arg(4) };

    // Parameter 1: tuple.
    let socktuple_len = if ret == 0 || ret == -defs::EINPROGRESS {
        let file: File = wrap_arg(unsafe { ctx.arg(0) });
        let sock = Socket::wrap(file.private_data().unwrap_or(null_mut()).cast());
        let sockaddr: Sockaddr = wrap_arg(unsafe { ctx.arg(1) });
        auxmap.store_sock_tuple_param(&sock, true, &sockaddr, true)
    } else {
        auxmap.store_empty_param();
        0
    };

    if unsafe { (*info).is_iou } {
        unsafe { (*info).socktuple_len = socktuple_len };
        return Ok(0);
    }

    // Parameter 2: iou_ret.
    auxmap.store_empty_param();

    // Parameter 3: res.
    auxmap.store_param(ret as i64);

    // Parameter 4: fd.
    // Parameter 5: file_index.
    auxmap.store_file_descriptor_param(unsafe { (*info).file_descriptor });

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}

#[fexit]
fn io_connect_x(ctx: FExitContext) -> u32 {
    try_io_connect_x(ctx).unwrap_or(1)
}

fn try_io_connect_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let info_map = maps::get_info_map();
    let Some(&info) = (unsafe { info_map.get(&pid) }) else {
        return Err(1);
    };

    let _ = helpers::try_remove_map_entry(info_map, &pid);

    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Connect);

    // Parameter 1: tuple. (Already populated on fexit:__sys_connect_file)
    auxmap.skip_param(info.socktuple_len);

    // Parameter 2: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    auxmap.store_param(iou_ret);

    // Parameter 3: res.
    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    match iouring::io_kiocb_cqe_res(&req, iou_ret) {
        Ok(Some(cqe_res)) => auxmap.store_param(cqe_res as i64),
        _ => auxmap.store_empty_param(),
    }

    // Parameter 4: fd.
    // Parameter 5: file_index.
    auxmap.store_file_descriptor_param(info.file_descriptor);

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}

#[fexit]
fn __sys_connect_x(ctx: FExitContext) -> u32 {
    let pid = ctx.pid();
    helpers::try_remove_map_entry(maps::get_info_map(), &pid).unwrap_or(1)
}
