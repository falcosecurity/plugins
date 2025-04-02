use aya_ebpf::cty::{c_int, c_uint};
use aya_ebpf::helpers::bpf_probe_read_kernel;
use crate::vmlinux;
use crate::vmlinux::u32_;

/// Returns `req->flags`.
pub fn extract_io_kiocb_flags(req: *const vmlinux::io_kiocb) -> Result<c_uint, i64> {
    unsafe { bpf_probe_read_kernel(&(*req).flags) }
}

/// Returns `req->cqe.fd`.
pub fn extract_io_kiocb_cqe_fd(req: *const vmlinux::io_kiocb) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*req).cqe.__bindgen_anon_1.fd) }
}

/// Returns `req->cqe.res`.
pub fn extract_io_kiocb_cqe_res(req: *const vmlinux::io_kiocb) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*req).cqe.res) }
}

/// Returns `sock->file_slot`.
pub fn extract_io_socket_file_slot(sock: *const vmlinux::io_socket) -> Result <u32_, i64> {
    unsafe { bpf_probe_read_kernel(&(*sock).file_slot) }
}

/// Returns `sock->domain`.
pub fn extract_io_socket_domain(sock: *const vmlinux::io_socket) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*sock).domain) }
}

/// Returns `sock->type`.
pub fn extract_io_socket_type(sock: *const vmlinux::io_socket) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*sock).type_) }
}

/// Returns `sock->protocol`.
pub fn extract_io_socket_protocol(sock: *const vmlinux::io_socket) -> Result<c_int, i64> {
    unsafe { bpf_probe_read_kernel(&(*sock).protocol) }
}