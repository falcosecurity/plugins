//! # Data extraction
//!
//! ## Kernel functions call graph (`socket` and `socketcall` syscalls path)
//! ```
//! int __sys_socket(int family, int type, int protocol)
//!     static int sock_map_fd(struct socket *sock, int flags)
//!         struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
//!         void fd_install(unsigned int fd, struct file *file)
//! ```
//!
//! ## Kernel functions call graph (`io_uring` path)
//! ```
//! io_socket(struct io_kiocb *req, unsigned int issue_flags)
//!     struct file *__sys_socket_file(int family, int type, int protocol)
//!         static struct socket *__sys_socket_create(int family, int type, int protocol)
//!         struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
//!     if (...) void fd_install(unsigned int fd, struct file *file)
//!     else int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
//!         struct file *file, unsigned int file_slot)
//! ```
//!
//! ## Extraction flow
//! 1. `fexit:__sys_socket` | `fexit:io_socket`

use crate::{defs, iouring, shared_maps, vmlinux, FileDescriptor};
use aya_ebpf::cty::c_int;
use aya_ebpf::macros::fexit;
use aya_ebpf::programs::FExitContext;
use krsi_common::EventType;

#[fexit]
fn io_socket_x(ctx: FExitContext) -> u32 {
    try_io_socket_x(ctx).unwrap_or(1)
}

fn try_io_socket_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Socket);

    let req: *const vmlinux::io_kiocb = unsafe { ctx.arg(0) };
    let cmd = unsafe { &raw const (*req).__bindgen_anon_1.cmd };
    let sock: *const vmlinux::io_socket = cmd.cast();

    let iou_ret: c_int = unsafe { ctx.arg(2) };

    // Parameter 1: iou_ret.
    auxmap.store_param(iou_ret as i64);

    // Parameter 2: fd.
    // Parameter 3: file_index.
    match extract_file_descriptor(req, sock, iou_ret) {
        Ok(Some(file_descriptor)) => auxmap.store_file_descriptor_param(file_descriptor),
        _ => {
            auxmap.store_empty_param();
            auxmap.store_empty_param();
        }
    }

    // Parameter 4: domain.
    match iouring::extract_io_socket_domain(sock) {
        Ok(sock_domain) => auxmap.store_param(sock_domain as u32),
        Err(_) => auxmap.store_empty_param(),
    };

    // Parameter 5: type.
    match iouring::extract_io_socket_type(sock) {
        Ok(sock_type) => auxmap.store_param(sock_type as u32),
        Err(_) => auxmap.store_empty_param(),
    };

    // Parameter 6: proto.
    match iouring::extract_io_socket_protocol(sock) {
        Ok(sock_proto) => auxmap.store_param(sock_proto as u32),
        Err(_) => auxmap.store_empty_param(),
    };

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}

fn extract_file_descriptor(
    req: *const vmlinux::io_kiocb,
    sock: *const vmlinux::io_socket,
    iou_ret: c_int,
) -> Result<Option<FileDescriptor>, i64> {
    if iou_ret != defs::IOU_OK {
        return Ok(None);
    }
    let cqe_res = iouring::extract_io_kiocb_cqe_res(req)?;
    let file_slot = iouring::extract_io_socket_file_slot(sock)?;
    let fixed = file_slot != 0;
    Ok(Some(if !fixed {
        FileDescriptor::Fd(cqe_res)
    } else if cqe_res < 0 || file_slot == defs::IORING_FILE_INDEX_ALLOC {
        FileDescriptor::FileIndex(cqe_res)
    } else {
        FileDescriptor::FileIndex((file_slot - 1) as i32)
    }))
}

#[fexit]
fn __sys_socket_x(ctx: FExitContext) -> u32 {
    try___sys_socket_x(ctx).unwrap_or(1)
}

fn try___sys_socket_x(ctx: FExitContext) -> Result<u32, i64> {
    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Socket);

    // Parameter 1: iou_ret.
    auxmap.store_empty_param();

    // Parameter 2: fd.
    let ret: c_int = unsafe { ctx.arg(3) };
    auxmap.store_param(ret as i64);

    // Parameter 3: file_index.
    auxmap.store_empty_param();

    // Parameter 4: domain.
    let sock_domain: c_int = unsafe { ctx.arg(0) };
    auxmap.store_param(sock_domain as u32);

    // Parameter 5: type.
    let sock_type: c_int = unsafe { ctx.arg(1) };
    auxmap.store_param(sock_type as u32);

    // Parameter 6: proto.
    let sock_proto: c_int = unsafe { ctx.arg(2) };
    auxmap.store_param(sock_proto as u32);

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}
