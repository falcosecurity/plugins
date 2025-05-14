use core::ptr::null_mut;

use aya_ebpf::{
    cty::c_uchar,
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_str_bytes,
    },
};
use krsi_common::EventType;
use krsi_ebpf_core::{
    read_field, Filename, Path, Sock, Sockaddr, SockaddrIn, SockaddrIn6, SockaddrUn, Socket, Wrap,
};

use crate::{auxbuf, defs, scap, shared_state, sockets, FileDescriptor};

/// Wrapper around [auxbuf::Writer::preload_event_header] just collecting some additional
/// information before calling it.
pub fn preload_event_header(writer: &mut auxbuf::Writer, event_type: EventType) {
    let ts = shared_state::boot_time() + unsafe { bpf_ktime_get_boot_ns() };
    let tgid_pid = bpf_get_current_pid_tgid();
    let nparams = get_event_num_params(event_type) as u32;
    writer.preload_event_header(ts, tgid_pid, event_type, nparams);
}

fn get_event_num_params(event_type: EventType) -> u8 {
    match event_type.try_into() {
        // TODO(ekoops): try to generate the following numbers automatically.
        Ok(EventType::Open) => 8,
        Ok(EventType::Connect) => 5,
        Ok(EventType::Socket) => 6,
        Ok(EventType::Symlinkat) => 5,
        Ok(EventType::Linkat) => 7,
        Ok(EventType::Unlinkat) => 5,
        Ok(EventType::Mkdirat) => 5,
        Ok(EventType::Renameat) => 7,
        Ok(EventType::Bind) => 5,
        _ => 0,
    }
}

/// Stores the provided `file_descriptor` in the auxiliary buffer using the provided auxiliary
/// buffer `writer`.
pub fn store_file_descriptor_param(writer: &mut auxbuf::Writer, file_descriptor: FileDescriptor) {
    match file_descriptor.try_into() {
        Ok(FileDescriptor::Fd(fd)) => {
            writer.store_param(fd as i64);
            writer.store_empty_param();
        }
        Ok(FileDescriptor::FileIndex(file_index)) => {
            writer.store_empty_param();
            writer.store_param(file_index);
        }
    }
}

/// Stores the provided `filename` in the auxiliary buffer by using the provided auxiliary buffer
/// `writer`.
///
/// `is_kern_mem` denotes if the memory associated to the provided `filename` belongs to kernel or
/// user space.
///
/// This helper stores at maximum [MAX_PATH](defs::MAX_PATH) bytes of data: if the `filename` length
/// is bigger, it is capped to this amount. If the auxiliary buffer cannot accommodate at least
/// [MAX_PATH](defs::MAX_PATH) bytes, the operation is aborted.
pub fn store_filename_param(writer: &mut auxbuf::Writer, filename: &Filename, is_kern_mem: bool) {
    if let Err(_) = filename
        .name()
        .and_then(|name| store_charbuf_param(writer, name.cast(), is_kern_mem))
    {
        writer.store_empty_param();
    }
}

/// Stores the provided `path` in the auxiliary buffer by using the provided auxiliary buffer
/// `writer`.
///
/// This helper stores at maximum [MAX_PATH](defs::MAX_PATH) bytes of data: if the `path` length is
/// bigger, it is capped to this amount. If the auxiliary buffer cannot accommodate at least
/// [MAX_PATH](defs::MAX_PATH) bytes, the operation is aborted.
pub fn store_path_param(writer: &mut auxbuf::Writer, path: &Path) -> Result<u16, i64> {
    writer.store_var_len_param(defs::MAX_PATH, true, |mut param_writer| {
        let buf = param_writer.as_bytes();
        let written_bytes = unsafe { path.read_into(buf, buf.len() as u32)? };
        if written_bytes == 0 {
            // Push '\0' (empty string) and returns 1 as number of written bytes.
            param_writer.write_value::<u8>(0);
            return Ok(1);
        }
        return Ok(written_bytes as u16);
    })
}

/// Stores the provided `charbuf` in the auxiliary buffer by using the provided auxiliary buffer
/// `writer`.
///
/// `is_kern_mem` denotes if the memory associated to the provided `charbuf` belongs to kernel or
/// user space.
///
/// This helper stores at maximum [MAX_PATH](defs::MAX_PATH) bytes of data: if the `charbuf` length
/// is bigger, it is capped to this amount. If the auxiliary buffer cannot accommodate at least
/// [MAX_PATH](defs::MAX_PATH) bytes, the operation is aborted.
pub fn store_charbuf_param(
    writer: &mut auxbuf::Writer,
    charbuf: *const u8,
    is_kern_mem: bool,
) -> Result<u16, i64> {
    writer.store_var_len_param(defs::MAX_PATH, true, |mut param_writer| {
        write_charbuf(&mut param_writer, charbuf, is_kern_mem)
    })
}

fn write_charbuf(
    param_writer: &mut auxbuf::ParamWriter,
    charbuf: *const u8,
    is_kern_mem: bool,
) -> Result<u16, i64> {
    if charbuf.is_null() {
        return Ok(0);
    }
    let written_str = if is_kern_mem {
        unsafe { bpf_probe_read_kernel_str_bytes(charbuf, param_writer.as_bytes()) }?
    } else {
        unsafe { bpf_probe_read_user_str_bytes(charbuf, param_writer.as_bytes()) }?
    };
    // Note: the written buffer always includes the `\0` character.
    let written_bytes = written_str.len() + 1; // + 1 accounts for `\0`
    Ok(written_bytes as u16)
}

/// Stores the provided `sockaddr` in the auxiliary buffer by using the provided auxiliary buffer
/// `writer`.
///
/// `is_kern_mem` denotes if the memory associated to the provided `sockaddr` belongs to kernel or
/// user space.
///
/// Depending on the socket family, the `sockaddr` encoding can have a fixed or a variable length:
/// - in case of fixed length, if the encoding length is bigger than the amount of space in the
///   auxiliary buffer, the operation is aborted.
/// - in case of variable length, this helper stores at maximum [MAX_PATH](defs::MAX_PATH) bytes of
///   data; if the length is bigger, it is capped to this amount; if the auxiliary buffer cannot
///   accommodate at least [MAX_PATH](defs::MAX_PATH) bytes, the operation is aborted.
pub fn store_sockaddr_param(writer: &mut auxbuf::Writer, sockaddr: &Sockaddr, is_kern_mem: bool) {
    let sa_family = read_field!(sockaddr => sa_family, is_kern_mem);
    let Ok(sa_family) = sa_family else {
        writer.store_empty_param();
        return;
    };

    let result = match sa_family {
        defs::AF_INET => store_inet_sockaddr_param(writer, &sockaddr.as_sockaddr_in(), is_kern_mem),
        defs::AF_INET6 => {
            store_inet6_sockaddr_param(writer, &sockaddr.as_sockaddr_in6(), is_kern_mem)
        }
        defs::AF_UNIX => store_unix_sockaddr_param(writer, &sockaddr.as_sockaddr_un(), is_kern_mem),
        _ => Err(1),
    };
    if result.is_err() {
        writer.store_empty_param();
    }
}

fn store_inet_sockaddr_param(
    writer: &mut auxbuf::Writer,
    sockaddr: &SockaddrIn,
    is_kern_mem: bool,
) -> Result<(), i64> {
    let param_len = (defs::FAMILY_SIZE + defs::IPV4_SIZE + defs::PORT_SIZE) as u16;
    writer.store_fixed_len_param(param_len, |mut param_writer| {
        let addr = sockaddr.sin_addr();
        let ipv4_addr = read_field!(addr => s_addr, is_kern_mem).unwrap_or(0);
        let port = read_field!(sockaddr => sin_port, is_kern_mem).unwrap_or(0);
        param_writer.write_value(scap::encode_socket_family(defs::AF_INET));
        param_writer.write_value(ipv4_addr);
        param_writer.write_value(u16::from_be(port));
        Ok(())
    })
}

fn store_inet6_sockaddr_param(
    writer: &mut auxbuf::Writer,
    sockaddr: &SockaddrIn6,
    is_kern_mem: bool,
) -> Result<(), i64> {
    let param_len = (defs::FAMILY_SIZE + defs::IPV6_SIZE + defs::PORT_SIZE) as u16;
    writer.store_fixed_len_param(param_len, |mut param_writer| {
        let addr = sockaddr.sin6_addr();
        let ipv6_addr = read_field!(addr => in6_u, is_kern_mem).unwrap_or([0, 0, 0, 0]);
        let port = read_field!(sockaddr => sin6_port, is_kern_mem).unwrap_or(0);
        param_writer.write_value(scap::encode_socket_family(defs::AF_INET6));
        param_writer.write_value(ipv6_addr);
        param_writer.write_value(u16::from_be(port));
        Ok(())
    })
}

fn store_unix_sockaddr_param(
    writer: &mut auxbuf::Writer,
    sockaddr: &SockaddrUn,
    is_kern_mem: bool,
) -> Result<(), i64> {
    let max_param_len = (defs::FAMILY_SIZE + defs::UNIX_PATH_MAX) as u16;
    let mut path: [c_uchar; defs::UNIX_PATH_MAX] = [0; defs::UNIX_PATH_MAX];
    let _ = sockets::sockaddr_un_path_into(&sockaddr, is_kern_mem, &mut path);
    writer
        .store_var_len_param(max_param_len, true, |mut param_writer| {
            param_writer.write_value(scap::encode_socket_family(defs::AF_UNIX));
            let written_bytes = write_sockaddr_path(&mut param_writer, &mut path)?;
            Ok(defs::FAMILY_SIZE as u16 + written_bytes)
        })
        .map(|_| ())
}

fn write_sockaddr_path(
    param_writer: &mut auxbuf::ParamWriter,
    path: &[c_uchar; defs::UNIX_PATH_MAX],
) -> Result<u16, i64> {
    // Notice an exception in `sun_path` (https://man7.org/linux/man-pages/man7/unix.7.html):
    // an `abstract socket address` is distinguished (from a pathname socket) by the fact that
    // sun_path[0] is a null byte (`\0`). So in this case, we need to skip the initial `\0`.
    //
    // Warning: if you try to extract the path slice in a separate statement as follows, the
    // verifier will complain (maybe because it would lose information about slice length):
    // let path_ref = if path[0] == 0 {&path[1..]} else {&path[..]};
    if path[0] == 0 {
        let path_ref = &path[1..];
        write_charbuf(param_writer, path_ref.as_ptr().cast(), true)
    } else {
        let path_ref = &path[..];
        write_charbuf(param_writer, path_ref.as_ptr().cast(), true)
    }
}

/// Stores the sock tuple information, extracted by leveraging the provided `sock` and `sockaddr`,
/// in the auxiliary buffer by using the provided auxiliary buffer `writer`.
///
/// `is_outbound` denotes if the connection is outbound or not.
///
/// `is_kern_mem` denotes if the memory associated to the provided `sockaddr` belongs to kernel or
/// user space.
///
/// Depending on the socket family, the sock tuple encoding can have a fixed or a variable length:
/// - in case of fixed length, if the encoding length is bigger than the amount of space in the
///   auxiliary buffer, the operation is aborted.
/// - in case of variable length, this helper stores at maximum [MAX_PATH](defs::MAX_PATH) bytes of
///   data; if the length is bigger, it is capped to this amount; if the auxiliary buffer cannot
///   accommodate at least [MAX_PATH](defs::MAX_PATH) bytes, the operation is aborted.
pub fn store_sock_tuple_param(
    writer: &mut auxbuf::Writer,
    sock: &Socket,
    is_outbound: bool,
    sockaddr: &Sockaddr,
    is_kern_sockaddr: bool,
) -> u16 {
    if sock.is_null() {
        writer.store_empty_param();
        return 0;
    }

    let Ok(sk) = sock.sk() else {
        writer.store_empty_param();
        return 0;
    };

    let Ok(sk_family) = sk.__sk_common().skc_family() else {
        writer.store_empty_param();
        return 0;
    };

    let result = match sk_family {
        defs::AF_INET => {
            store_inet_sock_tuple_param(writer, &sk, is_outbound, sockaddr, is_kern_sockaddr)
        }
        defs::AF_INET6 => {
            store_inet6_sock_tuple_param(writer, &sk, is_outbound, sockaddr, is_kern_sockaddr)
        }
        defs::AF_UNIX => {
            store_unix_sock_tuple_param(writer, &sk, is_outbound, sockaddr, is_kern_sockaddr)
        }
        _ => {
            writer.store_empty_param();
            return 0;
        }
    };
    match result {
        Ok(written_bytes) => written_bytes,
        Err(_) => {
            writer.store_empty_param();
            0
        }
    }
}

fn store_inet_sock_tuple_param(
    writer: &mut auxbuf::Writer,
    sk: &Sock,
    is_outbound: bool,
    sockaddr: &Sockaddr,
    is_kern_sockaddr: bool,
) -> Result<u16, i64> {
    let inet_sk = sk.as_inet_sock();
    let ipv4_local = inet_sk.inet_saddr().unwrap_or(0);
    let port_local = inet_sk.inet_sport().unwrap_or(0);
    let mut ipv4_remote = sk.__sk_common().skc_daddr().unwrap_or(0);
    let mut port_remote = sk.__sk_common().skc_dport().unwrap_or(0);

    // Kernel doesn't always fill sk->__sk_common in sendto and sendmsg syscalls (as in the case
    // of a UDP connection). We fall back to the address from userspace when the kernel-provided
    // address is NULL.
    if port_remote == 0 && !sockaddr.is_null() {
        let sockaddr = sockaddr.as_sockaddr_in();
        if is_kern_sockaddr {
            ipv4_remote = sockaddr.sin_addr().s_addr().unwrap_or(0);
            port_remote = sockaddr.sin_port().unwrap_or(0);
        } else {
            ipv4_remote = sockaddr.sin_addr().s_addr_user().unwrap_or(0);
            port_remote = sockaddr.sin_port_user().unwrap_or(0);
        }
    }

    let param_len =
        (defs::FAMILY_SIZE + defs::IPV4_SIZE + defs::PORT_SIZE + defs::IPV4_SIZE + defs::PORT_SIZE)
            as u16;
    writer.store_fixed_len_param(param_len, |mut param_writer| {
        // Pack the tuple info: (sock_family, local_ipv4, local_port, remote_ipv4, remote_port)
        param_writer.write_value(scap::encode_socket_family(defs::AF_INET));
        if is_outbound {
            param_writer.write_value(ipv4_local);
            param_writer.write_value(u16::from_be(port_local));
            param_writer.write_value(ipv4_remote);
            param_writer.write_value(u16::from_be(port_remote));
        } else {
            param_writer.write_value(ipv4_remote);
            param_writer.write_value(u16::from_be(port_remote));
            param_writer.write_value(ipv4_local);
            param_writer.write_value(u16::from_be(port_local));
        }
        Ok(())
    })?;
    Ok(param_len)
}

fn store_inet6_sock_tuple_param(
    writer: &mut auxbuf::Writer,
    sk: &Sock,
    is_outbound: bool,
    sockaddr: &Sockaddr,
    is_kern_sockaddr: bool,
) -> Result<u16, i64> {
    let inet6_sk = sk.as_inet_sock();
    let ipv6_local = inet6_sk
        .pinet6()
        .and_then(|pinet6| pinet6.saddr().in6_u())
        .unwrap_or([0, 0, 0, 0]);
    let port_local = inet6_sk.inet_sport().unwrap_or(0);
    let mut ipv6_remote = sk
        .__sk_common()
        .skc_v6_daddr()
        .in6_u()
        .unwrap_or([0, 0, 0, 0]);
    let mut port_remote = sk.__sk_common().skc_dport().unwrap_or(0);

    // Kernel doesn't always fill sk->__sk_common in sendto and sendmsg syscalls (as in
    // the case of a UDP connection). We fall back to the address from userspace when
    // the kernel-provided address is NULL.
    if port_remote == 0 && !sockaddr.is_null() {
        let sockaddr = sockaddr.as_sockaddr_in6();
        if is_kern_sockaddr {
            ipv6_remote = sockaddr.sin6_addr().in6_u().unwrap_or([0, 0, 0, 0]);
            port_remote = sockaddr.sin6_port().unwrap_or(0);
        } else {
            ipv6_remote = sockaddr.sin6_addr().in6_u_user().unwrap_or([0, 0, 0, 0]);
            port_remote = sockaddr.sin6_port_user().unwrap_or(0);
        }
    }

    let len =
        (defs::FAMILY_SIZE + defs::IPV6_SIZE + defs::PORT_SIZE + defs::IPV6_SIZE + defs::PORT_SIZE)
            as u16;
    writer.store_fixed_len_param(len, |mut param_writer| {
        // Pack the tuple info: (sock_family, local_ipv6, local_port, remote_ipv6, remote_port)
        param_writer.write_value(scap::encode_socket_family(defs::AF_INET6));
        if is_outbound {
            param_writer.write_value(ipv6_local);
            param_writer.write_value(u16::from_be(port_local));
            param_writer.write_value(ipv6_remote);
            param_writer.write_value(u16::from_be(port_remote));
        } else {
            param_writer.write_value(ipv6_remote);
            param_writer.write_value(u16::from_be(port_remote));
            param_writer.write_value(ipv6_local);
            param_writer.write_value(u16::from_be(port_local));
        }
        Ok(())
    })?;
    Ok(len)
}

fn store_unix_sock_tuple_param(
    writer: &mut auxbuf::Writer,
    sk: &Sock,
    is_outbound: bool,
    sockaddr: &Sockaddr,
    is_kern_sockaddr: bool,
) -> Result<u16, i64> {
    let sk_local = sk.as_unix_sock();

    let sk_peer = sk_local.peer().unwrap_or(Sock::wrap(null_mut()));
    let sk_peer = sk_peer.as_unix_sock();

    let max_param_len =
        (defs::FAMILY_SIZE + defs::KERNEL_POINTER + defs::KERNEL_POINTER + defs::UNIX_PATH_MAX)
            as u16;

    writer.store_var_len_param(max_param_len, true, |mut param_writer| {
        let mut path: [c_uchar; defs::UNIX_PATH_MAX] = [0; defs::UNIX_PATH_MAX];
        let path_mut = &mut path;

        // Pack the tuple info: (sock_family, dest_os_ptr, src_os_ptr, dest_unix_path)
        param_writer.write_value(scap::encode_socket_family(defs::AF_UNIX));
        if is_outbound {
            param_writer.write_value(sk_peer.serialize_ptr() as u64);
            param_writer.write_value(sk_local.serialize_ptr() as u64);
            if sk_peer.is_null() && !sockaddr.is_null() {
                let sockaddr = sockaddr.as_sockaddr_un();
                let _ = sockets::sockaddr_un_path_into(&sockaddr, is_kern_sockaddr, path_mut);
            } else if !sk_peer.is_null() {
                let _ = sockets::unix_sock_addr_path_into(&sk_peer, path_mut);
            }
        } else {
            param_writer.write_value(sk_local.serialize_ptr() as u64);
            param_writer.write_value(sk_peer.serialize_ptr() as u64);
            let _ = sockets::unix_sock_addr_path_into(&sk_local, path_mut);
        }

        let written_bytes = write_sockaddr_path(&mut param_writer, &path).unwrap_or(0);
        let written_bytes = defs::FAMILY_SIZE
            + defs::KERNEL_POINTER
            + defs::KERNEL_POINTER
            + written_bytes as usize;
        Ok(written_bytes as u16)
    })
}
