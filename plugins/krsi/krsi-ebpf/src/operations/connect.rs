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

use crate::{defs, file, helpers, iouring, shared_maps, vmlinux, FileDescriptor};
use aya_ebpf::cty::c_int;
use aya_ebpf::macros::{fentry, fexit};
use aya_ebpf::programs::{FEntryContext, FExitContext};
use aya_ebpf::EbpfContext;
use core::ptr::null;
use krsi_common::EventType;

mod maps;

#[fentry]
fn io_connect_e(ctx: FEntryContext) -> u32 {
    try_io_connect_e(ctx).unwrap_or(1)
}

fn try_io_connect_e(ctx: FEntryContext) -> Result<u32, i64> {
    let req: *const vmlinux::io_kiocb = unsafe { ctx.arg(0) };
    // TODO(ekoops): handle flags in kernel versions using the `io_req_flags_t` type.
    let flags = iouring::extract_io_kiocb_flags(req)?;
    let fd = iouring::extract_io_kiocb_cqe_fd(req)?;

    const REQ_F_FIXED_FILE: u32 = 1;
    let file_descriptor = if flags & REQ_F_FIXED_FILE == 0 {
        FileDescriptor::Fd(fd)
    } else {
        FileDescriptor::FileIndex(fd)
    };
    let pid = ctx.pid();
    helpers::try_insert_map_entry(maps::get_conn_fds(), &pid, &file_descriptor)
}

#[fentry]
fn __sys_connect_e(ctx: FEntryContext) -> u32 {
    try___sys_connect_e(ctx).unwrap_or(1)
}

fn try___sys_connect_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let fd: c_int = unsafe { ctx.arg(0) };
    let file_descriptor = FileDescriptor::Fd(fd as i32);
    helpers::try_insert_map_entry(maps::get_conn_fds(), &pid, &file_descriptor)
}

#[fexit]
fn __sys_connect_file(ctx: FExitContext) -> u32 {
    try___sys_connect_file(ctx).unwrap_or(1)
}

fn try___sys_connect_file(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(file_descriptor) = (unsafe { maps::get_conn_fds().get(&pid) }) else {
        return Ok(0);
    };
    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::Connect);

    // Parameter 1: res.
    let ret: c_int = unsafe { ctx.arg(4) };
    auxmap.store_param(ret as i64);

    let file = file::File::new(unsafe { ctx.arg(0) });
    let sock: *const vmlinux::socket = file.extract_private_data().unwrap_or(null());

    // Parameter 2: tuple.
    if ret == 0 || ret == -defs::EINPROGRESS {
        let sockaddr: *const vmlinux::sockaddr = unsafe { ctx.arg(1) };
        auxmap.store_sock_tuple_param(sock, true, sockaddr, true);
    } else {
        auxmap.store_empty_param();
    }

    // Parameter 3: fd.
    // Parameter 4: file_index.
    auxmap.store_file_descriptor_param(*file_descriptor);

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}

#[fexit]
fn io_connect_x(ctx: FExitContext) -> u32 {
    let pid = ctx.pid();
    helpers::try_remove_map_entry(maps::get_conn_fds(), &pid).unwrap_or(1)
}

#[fexit]
fn __sys_connect_x(ctx: FExitContext) -> u32 {
    let pid = ctx.pid();
    helpers::try_remove_map_entry(maps::get_conn_fds(), &pid).unwrap_or(1)
}
