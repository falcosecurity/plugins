//! # Data extraction
//!
//! ## Kernel functions call graph (`bind` syscall path)
//! ```
//! SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
//!     int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
//!         int __sys_bind_socket(struct socket *sock, struct sockaddr_storage *address,
//!             int addrlen)
//! ```
//!
//! ## Kernel functions call graph (`socketcall` syscall path)
//! ```
//! SYSCALL_DEFINE2(socketcall, int, call, unsigned long __user *, args)
//!     int __sys_bind(int fd, struct sockaddr __user *umyaddr, int addrlen)
//!         int __sys_bind_socket(struct socket *sock, struct sockaddr_storage *address,
//!             int addrlen)
//! ```
//!
//! ## Kernel function call graph (`io_uring` path)
//! ```
//! int io_bind(struct io_kiocb *req, unsigned int issue_flags)
//!     int __sys_bind_socket(struct socket *sock, struct sockaddr_storage *address, int addrlen)
//! ```
//!
//! ## Extraction flow
//! 1. `fentry:io_bind`
//! 2. `fexit:io_bind` | `fexit:__sys_bind`

mod maps;

use aya_ebpf::{
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
    EbpfContext,
};
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, IoAsyncMsghdr, IoKiocb, Sockaddr};

use crate::{helpers, iouring, shared_maps, FileDescriptor};

#[fentry]
fn io_bind_e(ctx: FEntryContext) -> u32 {
    try_io_bind_e(ctx).unwrap_or(1)
}

fn try_io_bind_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    let file_descriptor = iouring::io_kiocb_cqe_file_descriptor(&req)?;
    helpers::try_insert_map_entry(maps::get_file_descriptors_map(), &pid, &file_descriptor)
}

#[fexit]
fn io_bind_x(ctx: FExitContext) -> u32 {
    try_io_bind_x(ctx).unwrap_or(1)
}

fn try_io_bind_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let file_descriptors_map = maps::get_file_descriptors_map();
    let Some(&file_descriptor) = (unsafe { file_descriptors_map.get(&pid) }) else {
        return Err(1);
    };

    let _ = helpers::try_remove_map_entry(file_descriptors_map, &pid);

    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Bind);

    // Parameter 1: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    auxmap.store_param(iou_ret);

    // Parameter 2: res.
    let req: IoKiocb = wrap_arg(unsafe { ctx.arg(0) });
    match iouring::io_kiocb_cqe_res(&req, iou_ret) {
        Ok(Some(cqe_res)) => auxmap.store_param(cqe_res as i64),
        _ => auxmap.store_empty_param(),
    }

    // Parameter 3: addr.
    match req.async_data_as::<IoAsyncMsghdr>() {
        Ok(io) => auxmap.store_sockaddr_param(&io.addr(), true),
        Err(_) => auxmap.store_empty_param(),
    };

    // Parameter 4: fd.
    // Parameter 5: file_index.
    auxmap.store_file_descriptor_param(file_descriptor);

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}

#[fexit]
#[allow(non_snake_case)]
fn __sys_bind_x(ctx: FExitContext) -> u32 {
    try___sys_bind_x(ctx).unwrap_or(1)
}

#[allow(non_snake_case)]
fn try___sys_bind_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Bind);

    // Parameter 1: iou_ret.
    auxmap.store_empty_param();

    // Parameter 2: res.
    let res: i64 = unsafe { ctx.arg(3) };
    auxmap.store_param(res);

    // Parameter 3: addr.
    let sockaddr: Sockaddr = wrap_arg(unsafe { ctx.arg(1) });
    auxmap.store_sockaddr_param(&sockaddr, false);

    // Parameter 4: fd.
    // Parameter 5: file_index.
    let fd = unsafe { ctx.arg(0) };
    let file_descriptor = FileDescriptor::Fd(fd);
    auxmap.store_file_descriptor_param(file_descriptor);

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}
