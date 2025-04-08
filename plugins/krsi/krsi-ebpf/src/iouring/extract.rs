use aya_ebpf::{
    cty::{c_int, c_uint},
    helpers::bpf_probe_read_kernel,
};

use crate::{vmlinux, vmlinux::u32_};

/// Returns `req->flags`.
pub fn io_kiocb_flags(req: *const vmlinux::io_kiocb) -> Result<c_uint, i64> {
    // TODO(ekoops): handle flags in kernel versions using the `io_req_flags_t` type.
    unsafe { bpf_probe_read_kernel(&(*req).flags) }
}

/// Returns `req->file`.
pub fn io_kiocb_file(req: *const vmlinux::io_kiocb) -> Result<*mut vmlinux::file, i64> {
    unsafe { bpf_probe_read_kernel(&(*req).__bindgen_anon_1.file) }
}

/// Returns `(io_async_msghdr *) req->async_data`.
pub fn io_kiocb_async_data(
    req: *const vmlinux::io_kiocb,
) -> Result<*const vmlinux::io_async_msghdr, i64> {
    unsafe {
        bpf_probe_read_kernel(
            &(*req)
                .async_data
                .cast_const()
                .cast::<vmlinux::io_async_msghdr>(),
        )
    }
}

/// Returns `(T *) &req.cmd`.
pub fn io_kiocb_cmd_ptr<T>(req: *const vmlinux::io_kiocb) -> *const T {
    unsafe { &raw const (*req).__bindgen_anon_1.cmd }.cast::<T>()
}

/// Returns `req->cqe.fd`.
pub fn io_kiocb_cqe_fd(req: *const vmlinux::io_kiocb) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*req).cqe.__bindgen_anon_1.fd) }
}

/// Returns `req->cqe.res`.
pub fn io_kiocb_cqe_res(req: *const vmlinux::io_kiocb) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*req).cqe.res) }
}

/// Returns `sock->file_slot`.
pub fn io_socket_file_slot(sock: *const vmlinux::io_socket) -> Result<u32_, i64> {
    unsafe { bpf_probe_read_kernel(&(*sock).file_slot) }
}

/// Returns `sock->domain`.
pub fn io_socket_domain(sock: *const vmlinux::io_socket) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*sock).domain) }
}

/// Returns `sock->type`.
pub fn io_socket_type(sock: *const vmlinux::io_socket) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*sock).type_) }
}

/// Returns `sock->protocol`.
pub fn io_socket_protocol(sock: *const vmlinux::io_socket) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*sock).protocol) }
}

/// Returns `io->addr`.
pub fn io_async_msghdr_addr_ptr(
    io: *const vmlinux::io_async_msghdr,
) -> *const vmlinux::__kernel_sockaddr_storage {
    unsafe { &raw const (*io).addr }
}

/// Return `un->flags`.
pub fn io_unlink_flags(un: *const vmlinux::io_unlink) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*un).flags) }
}

/// Return `un->dfd`.
pub fn io_unlink_dfd(un: *const vmlinux::io_unlink) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*un).dfd) }
}

/// Return `un->filename`.
pub fn io_unlink_filename(un: *const vmlinux::io_unlink) -> Result<*const vmlinux::filename, i64> {
    let filename = unsafe { bpf_probe_read_kernel(&(*un).filename) }?;
    Ok(filename.cast_const())
}

/// Return `ren->oldpath`.
pub fn io_rename_oldpath(ren: *const vmlinux::io_rename) -> Result<*const vmlinux::filename, i64> {
    let filename = unsafe { bpf_probe_read_kernel(&(*ren).oldpath) }?;
    Ok(filename.cast_const())
}

/// Return `ren->newpath`.
pub fn io_rename_newpath(ren: *const vmlinux::io_rename) -> Result<*const vmlinux::filename, i64> {
    let filename = unsafe { bpf_probe_read_kernel(&(*ren).newpath) }?;
    Ok(filename.cast_const())
}

/// Return `ren->old_dfd`.
pub fn io_rename_old_dfd(ren: *const vmlinux::io_rename) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*ren).old_dfd) }
}

/// Return `ren->new_dfd`.
pub fn io_rename_new_dfd(ren: *const vmlinux::io_rename) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*ren).new_dfd) }
}

/// Return `ren->flags`.
pub fn io_rename_flags(ren: *const vmlinux::io_rename) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*ren).flags) }
}
