use aya_ebpf::{
    cty::c_uchar,
    helpers::{bpf_probe_read_kernel_buf, bpf_probe_read_user_buf},
};
use krsi_ebpf_core::{ffi::sockaddr_un, SockaddrUn, UnixSock, Wrap};

use crate::defs;

/// Equivalent to `*path = sk->addr->name[0].sun_path`.
pub fn unix_sock_addr_path_into(
    sk: &UnixSock,
    path: &mut [c_uchar; defs::UNIX_PATH_MAX],
) -> Result<(), i64> {
    let addr = sk.addr()?;
    let len = addr.len()?;
    if len == 0 {
        return Ok(());
    }

    let first_sockaddr = unsafe { SockaddrUn::wrap(addr.name().cast::<sockaddr_un>()) };
    let sun_path = first_sockaddr.sun_path();
    unsafe { bpf_probe_read_kernel_buf(sun_path.cast(), path) }
}

/// Equivalent to `*path = sockaddr->sun_path`.
pub fn sockaddr_un_path_into(
    sockaddr: &SockaddrUn,
    is_kern_mem: bool,
    path: &mut [c_uchar; defs::UNIX_PATH_MAX],
) -> Result<(), i64> {
    let sun_path = sockaddr.sun_path();
    if is_kern_mem {
        unsafe { bpf_probe_read_kernel_buf(sun_path.cast(), path) }
    } else {
        unsafe { bpf_probe_read_user_buf(sun_path.cast(), path) }
    }
}
