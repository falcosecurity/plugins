//! # Data extraction upon socket creation procedures
//!
//! ## Kernel functions call graph (syscall path)
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
//! 1. `fentry:__sys_socket` | `fentry:io_socket` - detect the start of a socket creation procedure
//! and annotate it by putting the current task's pid in the `SOCK_PIDS` map
//! 2. `fexit:sock_alloc_file` - verify that socket creation has been accepted and, if the
//! `sock_alloc_file` operation was successful, extract the socket struct pointer, write the
//! association between the current task's pid and the extracted socket struct pointer in the
//! `SOCK_PTRS` map. In any case, remove the association for the current task's pid from the
//! `SOCK_PIDS` map.
//! 3. `fentry:fd_install` | `fexit:io_fixed_fd_install` - verify that a socket creation request is
//! currently in progress by checking the presence of an association for the current task's pid in
//! the `SOCK_PTRS` map, extract the socket struct pointer from the aforementioned association and
//! write the association (sock_struct_ptr, tgid) -> fd in the `SOCK_RES` map. In any case, remove
//! the association for the current task's pid from `SOCK_PTRS`
//! 4. `fexit:__sys_socket` | `fexit:io_socket` - ensure the associations for the current task's pid
//! are removed from the `SOCK_PIDS` and `SOCK_PTRS` maps
//!
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

use crate::connect::maps::SockPtrTgid;
use crate::{defs, file, scap, shared_maps, sockets, vmlinux, FileDescriptor};
use aya_ebpf::cty::{c_int, c_long, c_uint, c_ulong};
use aya_ebpf::helpers::bpf_probe_read_kernel;
use aya_ebpf::macros::{fentry, fexit};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{FEntryContext, FExitContext};
use aya_ebpf::{bpf_printk, EbpfContext};
use aya_log_ebpf::info;
use core::ffi::c_void;
use core::ptr::null;
use krsi_common::EventType;

mod maps;

// Socket creation handling part.

#[fentry]
fn __sys_socket_e(ctx: FEntryContext) -> u32 {
    let pid = ctx.pid();
    const ZERO: u32 = 0;
    try_insert_entry(maps::get_sock_pids_map(), &pid, &ZERO).unwrap_or(1)
}

#[fentry]
fn io_socket_e(ctx: FEntryContext) -> u32 {
    let pid = ctx.pid();
    const ZERO: u32 = 0;
    try_insert_entry(maps::get_sock_pids_map(), &pid, &ZERO).unwrap_or(1)
}

#[fexit]
fn sock_alloc_file(ctx: FExitContext) -> u32 {
    try_sock_alloc_file(ctx).unwrap_or(1)
}

fn try_sock_alloc_file(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let sock_pids_map = maps::get_sock_pids_map();
    if unsafe { sock_pids_map.get(&pid) }.is_none() {
        return Ok(0);
    }

    let file: *const vmlinux::file = unsafe { ctx.arg(3) };
    // TODO: verify that the following is the correct check condition
    if is_err(file) {
        return try_remove_entry(sock_pids_map, &pid);
    }

    let sock: usize = unsafe { ctx.arg(0) };
    let res = try_insert_entry(maps::get_sock_ptrs_map(), &pid, &sock);
    try_remove_entry(sock_pids_map, &pid).and(res)
}

fn is_err(file: *const vmlinux::file) -> bool {
    const MAX_ERRNO: c_long = 4095;

    // taken from kernel https://elixir.bootlin.com/linux/v6.13.7/source/include/linux/err.h#L28
    ((file as *const c_void) as c_ulong) >= ((-MAX_ERRNO) as c_ulong)
}

pub fn try_fd_install(
    ctx: &FExitContext,
    file_descriptor: FileDescriptor,
    file: &file::File,
) -> Result<u32, i64> {
    let pid = ctx.pid();
    let sock_ptrs_map = maps::get_sock_ptrs_map();
    let Some(&sock) = (unsafe { sock_ptrs_map.get(&pid) }) else {
        return Ok(0);
    };

    let tgid = ctx.tgid();
    let sock_ptr_tgid = SockPtrTgid {
        sock_ptr: sock,
        tgid,
    };

    let res = try_insert_entry(maps::get_sock_res_amp(), &sock_ptr_tgid, &file_descriptor);
    #[cfg(debug_assertions)]
    match file_descriptor {
        FileDescriptor::Fd(fd) => info!(
            ctx,
            "[fd_install][socket]: new association (sock={}, tgid={}) -> fd={}", sock, tgid, fd
        ),
        FileDescriptor::FileIndex(file_index) => info!(
            ctx,
            "[fd_install][socket]: new association (sock={}, tgid={}) -> file_index={}",
            sock,
            tgid,
            file_index
        ),
    };

    try_remove_entry(sock_ptrs_map, &pid).and(res)
}

#[fexit]
fn __sys_socket_x(ctx: FExitContext) -> u32 {
    let pid = ctx.pid();
    let res1 = try_remove_entry(maps::get_sock_pids_map(), &pid);
    let res2 = try_remove_entry(maps::get_sock_ptrs_map(), &pid);
    res1.and(res2).unwrap_or(1)
}

#[fexit]
fn io_socket_x(ctx: FExitContext) -> u32 {
    let pid = ctx.pid();
    let res1 = try_remove_entry(maps::get_sock_pids_map(), &pid);
    let res2 = try_remove_entry(maps::get_sock_ptrs_map(), &pid);
    res1.and(res2).unwrap_or(1)
}

fn try_insert_entry<K, V>(map: &HashMap<K, V>, key: &K, value: &V) -> Result<u32, i64> {
    match map.insert(key, value, 0) {
        Ok(()) => Ok(0),
        Err(_) => Err(1),
    }
}

fn try_remove_entry<K, V>(map: &HashMap<K, V>, key: &K) -> Result<u32, i64> {
    match map.remove(key) {
        Ok(_) => Ok(0),
        Err(_) => Err(1),
    }
}

// Socket connection handling part.

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

    let sock_ptr_tgid = SockPtrTgid::new(sock as usize, tgid);
    match unsafe { maps::get_sock_res_amp().get(&sock_ptr_tgid) } {
        Some(file_descriptor) => Ok(*file_descriptor),
        None => Err(1),
    }
}
