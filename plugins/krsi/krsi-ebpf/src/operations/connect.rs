//! # Data extraction upon socket connection procedures
//!
//! ## Kernel functions call graph
//! ```
//! int __sys_connect_file(struct file *file, struct sockaddr_storage *address, int addrlen, int file_flags)
//!     int security_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
//!     int (*connect)(struct sock *sk, struct sockaddr *uaddr, int addr_len);
//! ```
//!
//! ## Extraction flow
//! 3. `fexit:__sys_connect_file` - extract the relevant parameters for the connection request,
//! build the event in the auxiliary map and submit it.

use crate::{defs, file, scap, shared_maps, vmlinux, FileDescriptor};
use aya_ebpf::cty::{c_int};
use aya_ebpf::macros::fexit;
use aya_ebpf::programs::FExitContext;
use aya_ebpf::EbpfContext;
use core::ptr::null;
use krsi_common::EventType;

mod maps;

#[fexit]
fn __sys_connect_file(ctx: FExitContext) -> u32 {
    try___sys_connect_file(ctx).unwrap_or(1)
}

fn try___sys_connect_file(ctx: FExitContext) -> Result<u32, i64> {
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
    match get_file_descriptor(sock, ctx.tgid()) {
        Ok(file_descriptor) => {
            let (fd, file_index) = scap::encode_file_descriptor(file_descriptor);
            auxmap.store_param(fd as i64);
            auxmap.store_param(file_index);
        }
        Err(_) => {
            auxmap.store_empty_param(); // Store empty fd parameter.
            auxmap.store_empty_param(); // Store empty file_index parameter.
        }
    }

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}

fn get_file_descriptor(sock: *const vmlinux::socket, tgid: u32) -> Result<FileDescriptor, i64> {
    if sock.is_null() {
        return Err(1);
    }

    let sock_ptr_tgid = crate::operations::socket::SockPtrTgid::new(sock as usize, tgid);
    match unsafe { crate::operations::socket::get_sock_res_amp().get(&sock_ptr_tgid) } {
        Some(file_descriptor) => Ok(*file_descriptor),
        None => Err(1),
    }
}
