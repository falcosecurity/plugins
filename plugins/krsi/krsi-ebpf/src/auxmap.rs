use core::ptr::null;

use aya_ebpf::{
    bindings::BPF_RB_FORCE_WAKEUP,
    cty::{c_char, c_uchar},
    helpers::{
        bpf_d_path, bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns,
        bpf_probe_read_kernel_str_bytes, bpf_probe_read_user_str_bytes,
    },
};
use krsi_common::{EventHeader, EventType};

use crate::{
    defs, files, get_event_num_params, scap, shared_maps, sockets::extract, vmlinux, FileDescriptor,
};

// Event maximum size.
const MAX_EVENT_SIZE: u64 = 8 * 1024;

// Parameter maximum size.
const MAX_PARAM_SIZE: u64 = MAX_EVENT_SIZE - 1;

const AUXILIARY_MAP_SIZE: usize = 16 * 1024;

pub struct AuxiliaryMap {
    // raw space to save our variable-size event.
    pub data: [u8; AUXILIARY_MAP_SIZE],
    // position of the first empty byte in the `data` buffer.
    pub payload_pos: u64,
    // position of the first empty slot into the lengths array of the event.
    pub lengths_pos: u8,
    // event type we want to send to userspace.
    pub event_type: u16,
}

impl AuxiliaryMap {
    fn event_header_mut(&mut self) -> &mut EventHeader {
        unsafe { &mut *self.data.as_mut_ptr().cast::<EventHeader>() }
    }

    pub fn preload_event_header(&mut self, event_type: EventType) {
        let evt_hdr = self.event_header_mut();
        let nparams = get_event_num_params(event_type);
        evt_hdr.nparams = nparams as u32;
        evt_hdr.ts = shared_maps::get_boot_time() + unsafe { bpf_ktime_get_boot_ns() };
        evt_hdr.tgid_pid = bpf_get_current_pid_tgid();
        evt_hdr.evt_type = event_type;
        self.payload_pos =
            (size_of::<EventHeader>() + (nparams as usize) * size_of::<u16>()) as u64;
        self.lengths_pos = size_of::<EventHeader>() as u8;
        self.event_type = event_type as u16;
    }

    pub fn finalize_event_header(&mut self) {
        let payload_pos = self.payload_pos as u32;
        let evt_hdr = self.event_header_mut();
        evt_hdr.len = payload_pos;
    }

    pub fn store_param<T: Copy>(&mut self, param: T) {
        self.push(param);
        self.push_param_len(size_of::<T>() as u16);
    }

    pub fn store_empty_param(&mut self) {
        self.push_param_len(0);
    }

    /// This helper stores the charbuf pointed by `charbuf` into the auxmap. We read until we find
    /// a `\0`, if the charbuf length is greater than `max_len_to_read`, we read up to
    /// `max_len_to_read-1` bytes and add the `\0`. `is_kern_mem` allows to specify if the `charbuf`
    /// points to kernel or userspace memory. In case of error, the auxmap is left untouched.
    pub unsafe fn store_charbuf_param(
        &mut self,
        charbuf: *const c_uchar,
        max_len_to_read: u16,
        is_kern_mem: bool,
    ) -> Result<u16, i64> {
        let mut charbuf_len = 0_u16;
        if !charbuf.is_null() {
            charbuf_len = self.push_charbuf(charbuf, max_len_to_read as usize, is_kern_mem)?;
        }
        self.push_param_len(charbuf_len);
        Ok(charbuf_len)
    }

    /// This helper stores the path pointed by `path` into the auxmap. We read until we find a `\0`,
    /// if the path length is greater than `max_len_to_read`, we read up to `max_len_to_read-1`
    /// bytes and add the `\0`.
    pub unsafe fn store_path_param(
        &mut self,
        path: *const vmlinux::path,
        max_len_to_read: u16,
    ) -> Result<u16, i64> {
        let mut path_len = 0_u16;
        if !path.is_null() {
            path_len = self.push_path(path, max_len_to_read as usize)?;
        }
        self.push_param_len(path_len);
        Ok(path_len)
    }

    /// Store the socktuple obtained by extracting information from the provided socket and the
    /// provided sockaddr. Returns the stored lengths.
    pub fn store_sock_tuple_param(
        &mut self,
        sock: *const vmlinux::socket,
        is_outbound: bool,
        sockaddr: *const vmlinux::sockaddr,
        is_kern_sockaddr: bool,
    ) -> u16 {
        if sock.is_null() {
            self.store_empty_param();
            return 0;
        }

        let Ok(sk) = extract::socket_sk(sock) else {
            self.store_empty_param();
            return 0;
        };

        let Ok(sk_family) = extract::sock_family(sk) else {
            self.store_empty_param();
            return 0;
        };

        let final_parameter_len = match sk_family {
            defs::AF_INET => self.push_inet_sock_tuple(sk, is_outbound, sockaddr, is_kern_sockaddr),
            defs::AF_INET6 => {
                self.push_inet6_sock_tuple(sk, is_outbound, sockaddr, is_kern_sockaddr)
            }
            defs::AF_UNIX => self.push_unix_sock_tuple(sk, is_outbound, sockaddr, is_kern_sockaddr),
            _ => 0,
        } as u16;

        self.push_param_len(final_parameter_len);
        final_parameter_len
    }

    fn push_inet_sock_tuple(
        &mut self,
        sk: *const vmlinux::sock,
        is_outbound: bool,
        sockaddr: *const vmlinux::sockaddr,
        is_kern_sockaddr: bool,
    ) -> usize {
        let inet_sk = sk.cast::<vmlinux::inet_sock>();
        let ipv4_local = extract::inet_sock_saddr(inet_sk).unwrap_or(0);
        let port_local = extract::inet_sock_sport(inet_sk).unwrap_or(0);
        let mut ipv4_remote = extract::sock_inet_daddr(sk).unwrap_or(0);
        let mut port_remote = extract::sock_inet_dport(sk).unwrap_or(0);

        // Kernel doesn't always fill sk->__sk_common in sendto and sendmsg syscalls (as in the case
        // of a UDP connection). We fall back to the address from userspace when the kernel-provided
        // address is NULL.
        if port_remote == 0 && !sockaddr.is_null() {
            (ipv4_remote, port_remote) =
                extract::sockaddr_in_saddr_and_sport(sockaddr.cast(), is_kern_sockaddr)
                    .unwrap_or((0, 0));
        }

        // Pack the tuple info: (sock_family, local_ipv4, local_port, remote_ipv4, remote_port)
        self.push(scap::encode_socket_family(defs::AF_INET));
        if is_outbound {
            self.push(ipv4_local);
            self.push(u16::from_be(port_local));
            self.push(ipv4_remote);
            self.push(u16::from_be(port_remote));
        } else {
            self.push(ipv4_remote);
            self.push(u16::from_be(port_remote));
            self.push(ipv4_local);
            self.push(u16::from_be(port_local));
        }

        defs::FAMILY_SIZE + defs::IPV4_SIZE + defs::PORT_SIZE + defs::IPV4_SIZE + defs::PORT_SIZE
    }

    fn push_inet6_sock_tuple(
        &mut self,
        sk: *const vmlinux::sock,
        is_outbound: bool,
        sockaddr: *const vmlinux::sockaddr,
        is_kern_sockaddr: bool,
    ) -> usize {
        let inet6_sk = sk.cast::<vmlinux::inet_sock>();
        let ipv6_local = extract::sock_inet6_saddr(inet6_sk).unwrap_or([0, 0, 0, 0]);
        let port_local = extract::inet_sock_sport(inet6_sk).unwrap_or(0);
        let mut ipv6_remote = extract::sock_inet6_daddr(sk).unwrap_or([0, 0, 0, 0]);
        let mut port_remote = extract::sock_inet_dport(sk).unwrap_or(0);

        // Kernel doesn't always fill sk->__sk_common in sendto and sendmsg syscalls (as in
        // the case of a UDP connection). We fall back to the address from userspace when
        // the kernel-provided address is NULL.
        if port_remote == 0 && !sockaddr.is_null() {
            (ipv6_remote, port_remote) =
                extract::sockaddr_in6_saddr_and_sport(sockaddr.cast(), is_kern_sockaddr)
                    .unwrap_or(([0, 0, 0, 0], 0));
        }

        // Pack the tuple info: (sock_family, local_ipv6, local_port, remote_ipv6, remote_port)
        self.push(scap::encode_socket_family(defs::AF_INET6));
        if is_outbound {
            self.push(ipv6_local);
            self.push(u16::from_be(port_local));
            self.push(ipv6_remote);
            self.push(u16::from_be(port_remote));
        } else {
            self.push(ipv6_remote);
            self.push(u16::from_be(port_remote));
            self.push(ipv6_local);
            self.push(u16::from_be(port_local));
        }

        defs::FAMILY_SIZE + defs::IPV6_SIZE + defs::PORT_SIZE + defs::IPV6_SIZE + defs::PORT_SIZE
    }

    fn push_unix_sock_tuple(
        &mut self,
        sk: *const vmlinux::sock,
        is_outbound: bool,
        sockaddr: *const vmlinux::sockaddr,
        is_kern_sockaddr: bool,
    ) -> usize {
        let sk_local = sk.cast::<vmlinux::unix_sock>();
        let sk_peer = extract::unix_sock_peer(sk_local).unwrap_or(null());

        let mut path: [c_char; defs::UNIX_PATH_MAX] = [0; defs::UNIX_PATH_MAX];
        let path_mut = &mut path;

        // Pack the tuple info: (sock_family, dest_os_ptr, src_os_ptr, dest_unix_path)
        self.push(scap::encode_socket_family(defs::AF_UNIX));
        if is_outbound {
            self.push(sk_peer as u64);
            self.push(sk_local as u64);
            if sk_peer.is_null() && !sockaddr.is_null() {
                let sockaddr: *const vmlinux::sockaddr_un = sockaddr.cast();
                let _ = extract::sockaddr_un_path_into(sockaddr, is_kern_sockaddr, path_mut);
            } else {
                let _ = extract::unix_sock_addr_path_into(sk_peer, is_kern_sockaddr, path_mut);
            }
        } else {
            self.push(sk_local as u64);
            self.push(sk_peer as u64);
            let _ = extract::unix_sock_addr_path_into(sk_local, is_kern_sockaddr, path_mut);
        }

        // Notice an exception in `sun_path` (https://man7.org/linux/man-pages/man7/unix.7.html):
        // an `abstract socket address` is distinguished (from a pathname socket) by the fact that
        // sun_path[0] is a null byte (`\0`). So in this case, we need to skip the initial `\0`.
        //
        // Warning: if you try to extract the path slice in a separate statement as follows, the
        // verifier will complain (maybe because it would lose information about slice length):
        // let path_ref = if path[0] == 0 {&path[1..]} else {&path[..]};
        let written_bytes = if path[0] == 0 {
            let path_ref = &path[1..];
            self.push_charbuf(path_ref.as_ptr().cast(), path.len(), true)
        } else {
            let path_ref = &path[..];
            self.push_charbuf(path_ref.as_ptr().cast(), path.len(), true)
        }
        .unwrap_or(0);

        defs::FAMILY_SIZE + defs::KERNEL_POINTER + defs::KERNEL_POINTER + written_bytes as usize
    }

    pub fn store_file_descriptor_param(&mut self, file_descriptor: FileDescriptor) {
        match file_descriptor.try_into() {
            Ok(FileDescriptor::Fd(fd)) => {
                self.store_param(fd as i64);
                self.store_empty_param();
            }
            Ok(FileDescriptor::FileIndex(file_index)) => {
                self.store_empty_param();
                self.store_param(file_index);
            }
        }
    }

    pub fn skip_param(&mut self, len: u16) {
        self.payload_pos += len as u64;
        self.lengths_pos = self.lengths_pos + size_of::<u16>() as u8;
    }

    // Helper used to please the verifier during reading operations like `bpf_probe_read_str()`.
    fn data_safe_access(x: u64) -> usize {
        (x & MAX_PARAM_SIZE) as usize
    }

    fn push<T>(&mut self, value: T)
    where
        T: Copy,
    {
        let pos = Self::data_safe_access(self.payload_pos);
        unsafe {
            self.data
                .as_mut_ptr()
                .byte_add(pos)
                .cast::<T>()
                .write_unaligned(value);
        }
        self.payload_pos += size_of::<T>() as u64;
    }

    fn push_param_len(&mut self, value: u16) {
        let pos = Self::data_safe_access(self.lengths_pos as u64);
        unsafe {
            self.data
                .as_mut_ptr()
                .byte_add(pos)
                .cast::<u16>()
                .write_unaligned(value);
        }
        self.lengths_pos = self.lengths_pos + size_of::<u16>() as u8;
    }

    /// Try to push the char buffer pointed by `charbuf` into the underlying buffer. The maximum
    /// length of the char buffer can be at most `max_len_to_read`. In case of success, returns the
    /// number of written bytes. The written buffer always includes the `\0` character (even if it
    /// points to an empty C string), and this is accounted in the returned number of written bytes:
    /// this means that in case of success, a strictly positive integer is returned. `is_kern_mem`
    /// allows to specify if the `charbuf` points to kernel or userspace memory.
    fn push_charbuf(
        &mut self,
        charbuf: *const c_uchar,
        max_len_to_read: usize,
        is_kern_mem: bool,
    ) -> Result<u16, i64> {
        let pos = Self::data_safe_access(self.payload_pos);
        let limit = pos + max_len_to_read;
        let written_str = if is_kern_mem {
            unsafe { bpf_probe_read_kernel_str_bytes(charbuf, &mut self.data[pos..limit]) }?
        } else {
            unsafe { bpf_probe_read_user_str_bytes(charbuf, &mut self.data[pos..limit]) }?
        };
        let written_bytes = written_str.len() + 1; // + 1 accounts for `\0`
        self.payload_pos += written_bytes as u64;
        Ok(written_bytes as u16)
    }

    unsafe fn push_path(
        &mut self,
        path: *const vmlinux::path,
        max_len_to_read: usize,
    ) -> Result<u16, i64> {
        let path = path as *mut aya_ebpf::bindings::path;
        let data_pos = Self::data_safe_access(self.payload_pos);
        let data = (&mut self.data)
            .as_mut_ptr()
            .cast::<c_char>()
            .byte_add(data_pos);
        let max_len_to_read = max_len_to_read as u32;
        let written_bytes = bpf_d_path(path, data, max_len_to_read);
        if written_bytes < 0 {
            return Err(1);
        }
        if written_bytes == 0 {
            // Push '\0' and returns 1 as number of written bytes.
            self.push(0_u8);
            return Ok(1);
        }
        self.payload_pos += written_bytes as u64;
        Ok(written_bytes as u16)
    }

    pub fn store_filename_param(
        &mut self,
        filename: *const vmlinux::filename,
        max_len_to_read: u16,
        is_kern_mem: bool,
    ) {
        if let Err(_) = files::extract::filename_name(filename).and_then(|name| unsafe {
            self.store_charbuf_param(name, max_len_to_read, is_kern_mem)
        }) {
            self.store_empty_param();
        }
    }

    pub fn submit_event(&self) {
        if self.payload_pos > MAX_EVENT_SIZE {
            // TODO: account for drop.
            return;
        }

        let _ = shared_maps::get_events_ringbuf()
            .output(self.data.as_ref(), BPF_RB_FORCE_WAKEUP as u64);
    }
}
