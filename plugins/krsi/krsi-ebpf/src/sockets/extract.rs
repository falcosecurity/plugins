use aya_ebpf::{
    cty::c_char,
    helpers::{bpf_probe_read_kernel, bpf_probe_read_user},
};

use crate::{defs, vmlinux};

/// Returns `sock->sk`.
pub fn socket_sk(sock: *const vmlinux::socket) -> Result<*const vmlinux::sock, i64> {
    let sk: *mut vmlinux::sock = unsafe { bpf_probe_read_kernel(&(*sock).sk) }?;
    Ok(sk.cast_const())
}

/// Returns `sk->__sk_common.skc_family`.
pub fn sock_family(sk: *const vmlinux::sock) -> Result<u16, i64> {
    unsafe { bpf_probe_read_kernel(&(*sk).__sk_common.skc_family) }
}

/// Returns `sk->__sk_comm.skc_daddr`.
pub fn sock_inet_daddr(sk: *const vmlinux::sock) -> Result<u32, i64> {
    unsafe {
        bpf_probe_read_kernel(
            &(*sk)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_daddr,
        )
    }
}

/// Returns `sk->__sk_comm.skc_dport`.
pub fn sock_inet_dport(sk: *const vmlinux::sock) -> Result<u16, i64> {
    unsafe {
        bpf_probe_read_kernel(
            &(*sk)
                .__sk_common
                .__bindgen_anon_3
                .__bindgen_anon_1
                .skc_dport,
        )
    }
}

/// Returns `sk->pinet6->.saddr.in6_u.u6_addr32`.
pub fn sock_inet6_saddr(sk: *const vmlinux::inet_sock) -> Result<[u32; 4], i64> {
    let pinet6 = unsafe { bpf_probe_read_kernel(&(*sk).pinet6) }?;
    if pinet6.is_null() {
        return Err(1);
    }

    unsafe { bpf_probe_read_kernel(&(*pinet6).saddr.in6_u.u6_addr32) }
}

/// Returns `sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32`.
pub fn sock_inet6_daddr(sk: *const vmlinux::sock) -> Result<[u32; 4], i64> {
    unsafe { bpf_probe_read_kernel(&(*sk).__sk_common.skc_v6_daddr.in6_u.u6_addr32) }
}

/// Returns `sk->inet_saddr`.
pub fn inet_sock_saddr(sk: *const vmlinux::inet_sock) -> Result<u32, i64> {
    unsafe { bpf_probe_read_kernel(&(*sk).inet_saddr) }
}

/// Returns `sk->inet_sport`.
pub fn inet_sock_sport(sk: *const vmlinux::inet_sock) -> Result<u16, i64> {
    unsafe { bpf_probe_read_kernel(&(*sk).inet_sport) }
}

/// Returns `sk->peer`.
pub fn unix_sock_peer(sk: *const vmlinux::unix_sock) -> Result<*const vmlinux::unix_sock, i64> {
    let peer_sk: *mut vmlinux::sock = unsafe { bpf_probe_read_kernel(&(*sk).peer) }?;
    Ok(peer_sk.cast_const().cast())
}

/// Equivalent to `*path = sk->addr->name[0].sun_path`.
pub fn unix_sock_addr_path_into(
    sk: *const vmlinux::unix_sock,
    is_kern_mem: bool,
    path: &mut [c_char; defs::UNIX_PATH_MAX],
) -> Result<(), i64> {
    let addr = unsafe { bpf_probe_read_kernel(&(*sk).addr) }?;
    let name = unsafe { bpf_probe_read_kernel(&(*addr).name.as_ptr()) }?;
    sockaddr_un_path_into(name, is_kern_mem, path)
}

/// Returns `*sockaddr`.
fn sockaddr_in(
    sockaddr: *const vmlinux::sockaddr_in,
    is_kern_mem: bool,
) -> Result<vmlinux::sockaddr_in, i64> {
    if is_kern_mem {
        unsafe { bpf_probe_read_kernel(sockaddr) }
    } else {
        unsafe { bpf_probe_read_user(sockaddr) }
    }
}

/// Returns the tuple `(sockaddr->sin_addr.s_addr, sockaddr.sin_port)`.
pub fn sockaddr_in_saddr_and_sport(
    sockaddr: *const vmlinux::sockaddr_in,
    is_kern_mem: bool,
) -> Result<(u32, u16), i64> {
    let sa = sockaddr_in(sockaddr, is_kern_mem)?;
    Ok((sa.sin_addr.s_addr, sa.sin_port))
}

/// Returns `*sockaddr`.
fn sockaddr_in6(
    sockaddr: *const vmlinux::sockaddr_in6,
    is_kern_mem: bool,
) -> Result<vmlinux::sockaddr_in6, i64> {
    if is_kern_mem {
        unsafe { bpf_probe_read_kernel(sockaddr) }
    } else {
        unsafe { bpf_probe_read_user(sockaddr) }
    }
}

/// Returns the tuple `(sockaddr->sin6_addr.in6_u.u6_addr32, sockaddr.sin6_port)`.
pub fn sockaddr_in6_saddr_and_sport(
    sockaddr: *const vmlinux::sockaddr_in6,
    is_kern_mem: bool,
) -> Result<([u32; 4], u16), i64> {
    let sa = sockaddr_in6(sockaddr, is_kern_mem)?;
    Ok((unsafe { sa.sin6_addr.in6_u.u6_addr32 }, sa.sin6_port))
}

/// Returns `*sockaddr`.
fn sockaddr_un(
    sockaddr: *const vmlinux::sockaddr_un,
    is_kern_mem: bool,
) -> Result<vmlinux::sockaddr_un, i64> {
    if is_kern_mem {
        unsafe { bpf_probe_read_kernel(sockaddr) }
    } else {
        unsafe { bpf_probe_read_user(sockaddr) }
    }
}

/// Equivalent to `*path = sockaddr->sun_path`.
pub fn sockaddr_un_path_into(
    sockaddr: *const vmlinux::sockaddr_un,
    is_kern_mem: bool,
    path: &mut [c_char; defs::UNIX_PATH_MAX],
) -> Result<(), i64> {
    let sa = sockaddr_un(sockaddr, is_kern_mem)?;
    *path = sa.sun_path;
    Ok(())
}
