//! Kernel functions call graph:
//! ```
//! int __sys_socket(int family, int type, int protocol)
//!     static int sock_map_fd(struct socket *sock, int flags)
//!         struct file *sock_alloc_file(struct socket *sock, int flags, const char *dname)
//!         void fd_install(unsigned int fd, struct file *file)
//! ```
//!
//! Flow for extracting parameters upon socket creation procedures:
//! 1. `fentry:__sys_socket` - detect the start of a socket creation procedure and annotate it by
//! putting the current thread's tid in the `SOCK_TIDS` map
//! 2. `fexit:sock_alloc_file` - verify that socket creation has been accepted and, if the
//! `sock_alloc_file` operation was successful, extract the socket struct pointer, write the
//! association between the current thread's tid and the extracted socket struct pointer in the
//! `SOCK_PTRS` map. In any case, remove the association for the current thread's tid from the
//! `SOCK_TIDS` map.
//! 3. `fentry:fd_install` - verify that a socket creation request is currently in progress by
//! checking the presence of an association for the current thread's tid in the `SOCK_PTRS` map,
//! extract the socket struct pointer from the aforementioned association and write the association
//! (sock_struct_ptr, tgid) -> fd in the `SOCK_RES` map. In any case, remove the association for the
//! current thread's tid from `SOCK_PTRS`
//! 4. `fexit:__sys_socket` - ensure the associations for the current thread's tid are removed from
//! the `SOCK_TIDS` and `SOCK_PTRS` maps

use crate::connect::maps::SockPtrTgid;
use crate::vmlinux;
use aya_ebpf::cty::{c_long, c_ulong};
use aya_ebpf::macros::{fentry, fexit, kprobe, kretprobe};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{FEntryContext, FExitContext, ProbeContext, RetProbeContext};
use aya_ebpf::EbpfContext;
use aya_log_ebpf::info;
use core::ffi::c_void;

mod maps;

#[fentry]
fn __sys_socket_e(ctx: FEntryContext) -> u32 {
    let tid = ctx.pid();
    const ZERO: u32 = 0;
    try_insert_entry(maps::get_sock_tids_map(), &tid, &ZERO).unwrap_or(1)
}

#[fexit]
fn sock_alloc_file(ctx: FExitContext) -> u32 {
    try_sock_alloc_file(ctx).unwrap_or(1)
}

fn try_sock_alloc_file(ctx: FExitContext) -> Result<u32, i64> {
    let tid = ctx.pid();
    let sock_tids_map = maps::get_sock_tids_map();
    if unsafe { sock_tids_map.get(&tid) }.is_none() {
        return Ok(0);
    }

    let file_ptr: *const vmlinux::file = unsafe { ctx.arg(3) };
    // TODO: verify that the following is the correct check condition
    if is_err(file_ptr) {
        return try_remove_entry(sock_tids_map, &tid);
    }

    let sock_ptr: usize = unsafe { ctx.arg(0) };
    let res = try_insert_entry(maps::get_sock_ptrs_map(), &tid, &sock_ptr);
    try_remove_entry(sock_tids_map, &tid).and(res)
}

fn is_err(file_ptr: *const vmlinux::file) -> bool {
    const MAX_ERRNO: c_long = 4095;

    // taken from kernel https://elixir.bootlin.com/linux/v6.13.7/source/include/linux/err.h#L28
    ((file_ptr as *const c_void) as c_ulong) >= ((-MAX_ERRNO) as c_ulong)
}

pub fn try_fd_install(ctx: &FEntryContext) -> Result<u32, i64> {
    let tid = ctx.pid();
    let sock_ptrs_map = maps::get_sock_ptrs_map();
    let Some(&sock_ptr) = (unsafe { sock_ptrs_map.get(&tid) }) else {
        return Ok(0);
    };

    let fd = unsafe { ctx.arg(0) };
    let tgid = ctx.tgid();
    let sock_ptr_tgid = SockPtrTgid { sock_ptr, tgid };
    let res = try_insert_entry(maps::get_sock_res_amp(), &sock_ptr_tgid, &fd);
    #[cfg(debug_assertions)]
    info!(
        ctx,
        "[fd_install][socket]: new association (sock_ptr={}, tgid={}) -> fd={}", sock_ptr, tgid, fd
    );
    try_remove_entry(sock_ptrs_map, &tid).and(res)
}

#[fexit]
fn __sys_socket_x(ctx: FExitContext) -> u32 {
    let tid = ctx.pid();
    let res1 = try_remove_entry(maps::get_sock_tids_map(), &tid);
    let res2 = try_remove_entry(maps::get_sock_ptrs_map(), &tid);
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
