use crate::{defs, scap, shared_maps, sockets, vmlinux};
use aya_ebpf::bindings::BPF_RB_FORCE_WAKEUP;
use aya_ebpf::cty::{c_char, c_uchar};
use aya_ebpf::helpers::{
    bpf_d_path, bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, bpf_probe_read_kernel_str_bytes,
    bpf_probe_read_user_str_bytes,
};
use core::ptr::null;
use krsi_common::{EventHeader, EventType};

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
    unsafe fn get_event_header_mut(&mut self) -> &mut EventHeader {
        &mut *self.data.as_mut_ptr().cast::<EventHeader>()
    }

    pub unsafe fn preload_event_header(&mut self, event_type: EventType) {
        let evt_hdr = self.get_event_header_mut();
        let nparams = shared_maps::get_event_num_params(event_type);
        evt_hdr.nparams = nparams as u32;
        evt_hdr.ts = shared_maps::get_boot_time() + bpf_ktime_get_boot_ns();
        evt_hdr.tgid_pid = bpf_get_current_pid_tgid();
        evt_hdr.evt_type = event_type;
        self.payload_pos =
            (size_of::<EventHeader>() + (nparams as usize) * size_of::<u16>()) as u64;
        self.lengths_pos = size_of::<EventHeader>() as u8;
        self.event_type = event_type as u16;
    }

    pub unsafe fn finalize_event_header(&mut self) {
        let payload_pos = self.payload_pos as u32;
        let evt_hdr = self.get_event_header_mut();
        evt_hdr.len = payload_pos;
    }

    pub unsafe fn store_param<T: Copy>(&mut self, param: T) {
        self.push(param);
        self.push_param_len(size_of::<T>() as u16);
    }

    pub fn store_empty_param(&mut self) {
        self.push_param_len(0);
    }

    /// This helper stores the charbuf pointed by `charbuf_ptr` into the auxmap. We read until we
    /// find a `\0`, if the charbuf length is greater than `max_len_to_read`, we read up to
    /// `max_len_to_read-1` bytes and add the `\0`. `is_kern_mem` allows to specify if the
    /// `charbuf_ptr` points to kernel or userspace memory.
    ///
    pub unsafe fn store_charbuf_param(
        &mut self,
        charbuf_ptr: *const c_uchar,
        max_len_to_read: u16,
        is_kern_mem: bool,
    ) -> Result<u16, i64> {
        let mut charbuf_len = 0_u16;
        if !charbuf_ptr.is_null() {
            charbuf_len = self.push_charbuf(charbuf_ptr, max_len_to_read as usize, is_kern_mem)?;
        }
        self.push_param_len(charbuf_len);
        Ok(charbuf_len)
    }

    /// This helper stores the path pointed by `path_ptr` into the auxmap. We read until we find a
    /// `\0`, if the path length is greater than `max_len_to_read`, we read up to
    /// `max_len_to_read-1` bytes and add the `\0`.
    pub unsafe fn store_path_param(
        &mut self,
        path_ptr: *const vmlinux::path,
        max_len_to_read: u16,
    ) -> Result<u16, i64> {
        let mut path_len = 0_u16;
        if !path_ptr.is_null() {
            path_len = self.push_path(path_ptr, max_len_to_read as usize)?;
        }
        self.push_param_len(path_len);
        Ok(path_len)
    }

    pub fn store_sock_tuple_param(
        &mut self,
        sock_ptr: *const vmlinux::socket,
        is_outbound: bool,
        sockaddr_ptr: *const vmlinux::sockaddr,
        is_kern_mem_sockaddr_ptr: bool,
    ) {
        if sock_ptr.is_null() {
            self.store_empty_param();
            return;
        }

        let Ok(sk_ptr) = sockets::extract_socket_sk(sock_ptr) else {
            self.store_empty_param();
            return;
        };

        let Ok(sk_family) = sockets::extract_sock_family(sk_ptr) else {
            self.store_empty_param();
            return;
        };

        let final_parameter_len = match sk_family {
            defs::AF_INET => self.push_inet_sock_tuple(
                sk_ptr,
                is_outbound,
                sockaddr_ptr,
                is_kern_mem_sockaddr_ptr,
            ),
            defs::AF_INET6 => self.push_inet6_sock_tuple(
                sk_ptr,
                is_outbound,
                sockaddr_ptr,
                is_kern_mem_sockaddr_ptr,
            ),
            defs::AF_UNIX => self.push_unix_sock_tuple(
                sk_ptr,
                is_outbound,
                sockaddr_ptr,
                is_kern_mem_sockaddr_ptr,
            ),
            _ => 0,
        };

        self.push_param_len(final_parameter_len as u16);
    }

    fn push_inet_sock_tuple(
        &mut self,
        sk_ptr: *const vmlinux::sock,
        is_outbound: bool,
        sockaddr_ptr: *const vmlinux::sockaddr,
        is_kern_sockaddr_ptr: bool,
    ) -> usize {
        let inet_sk_ptr = sk_ptr.cast::<vmlinux::inet_sock>();
        let ipv4_local = sockets::extract_inet_sock_saddr(inet_sk_ptr).unwrap_or(0);
        let port_local = sockets::extract_inet_sock_sport(inet_sk_ptr).unwrap_or(0);
        let mut ipv4_remote = sockets::extract_sock_inet_daddr(sk_ptr).unwrap_or(0);
        let mut port_remote = sockets::extract_sock_inet_dport(sk_ptr).unwrap_or(0);

        // Kernel doesn't always fill sk->__sk_common in sendto and sendmsg syscalls (as in the case
        // of a UDP connection). We fall back to the address from userspace when the kernel-provided
        // address is NULL.
        if port_remote == 0 && !sockaddr_ptr.is_null() {
            (ipv4_remote, port_remote) = sockets::extract_sockaddr_in_saddr_and_sport(
                sockaddr_ptr.cast(),
                is_kern_sockaddr_ptr,
            )
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
        sk_ptr: *const vmlinux::sock,
        is_outbound: bool,
        usr_sockaddr_ptr: *const vmlinux::sockaddr,
        is_kern_sockaddr_ptr: bool,
    ) -> usize {
        let inet6_sk_ptr = sk_ptr.cast::<vmlinux::inet_sock>();
        let ipv6_local = sockets::extract_sock_inet6_saddr(inet6_sk_ptr).unwrap_or([0, 0, 0, 0]);
        let port_local = sockets::extract_inet_sock_sport(inet6_sk_ptr).unwrap_or(0);
        let mut ipv6_remote = sockets::extract_sock_inet6_daddr(sk_ptr).unwrap_or([0, 0, 0, 0]);
        let mut port_remote = sockets::extract_sock_inet_dport(sk_ptr).unwrap_or(0);

        // Kernel doesn't always fill sk->__sk_common in sendto and sendmsg syscalls (as in
        // the case of a UDP connection). We fall back to the address from userspace when
        // the kernel-provided address is NULL.
        if port_remote == 0 && !usr_sockaddr_ptr.is_null() {
            (ipv6_remote, port_remote) = sockets::extract_sockaddr_in6_saddr_and_sport(
                usr_sockaddr_ptr.cast(),
                is_kern_sockaddr_ptr,
            )
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
        sk_ptr: *const vmlinux::sock,
        is_outbound: bool,
        sockaddr_ptr: *const vmlinux::sockaddr,
        is_kern_sockaddr_ptr: bool,
    ) -> usize {
        let sk_local_ptr = sk_ptr.cast::<vmlinux::unix_sock>();
        let sk_peer_ptr = sockets::extract_unix_sock_peer(sk_local_ptr).unwrap_or(null());

        let mut path: [c_char; defs::UNIX_PATH_MAX] = [0; defs::UNIX_PATH_MAX];
        let path_mut = &mut path;

        // Pack the tuple info: (sock_family, dest_os_ptr, src_os_ptr, dest_unix_path)
        self.push(scap::encode_socket_family(defs::AF_UNIX));
        if is_outbound {
            self.push(sk_peer_ptr as u64);
            self.push(sk_local_ptr as u64);
            if sk_peer_ptr.is_null() && !sockaddr_ptr.is_null() {
                let _ = sockets::extract_sockaddr_un_path_into(
                    sockaddr_ptr.cast(),
                    is_kern_sockaddr_ptr,
                    path_mut,
                );
            } else {
                let _ = sockets::extract_unix_sock_addr_path_into(
                    sk_peer_ptr,
                    is_kern_sockaddr_ptr,
                    path_mut,
                );
            }
        } else {
            self.push(sk_local_ptr as u64);
            self.push(sk_peer_ptr as u64);
            let _ = sockets::extract_unix_sock_addr_path_into(
                sk_local_ptr,
                is_kern_sockaddr_ptr,
                path_mut,
            );
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

    pub fn skip_stored_param(&mut self, len: u16) {
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

    /// Try to push the char buffer pointed by `charbuf_ptr` into the underlying buffer.
    /// The maximum length of the char buffer can be at most `max_len_to_read`. In case of success,
    /// returns the number of written bytes. If the char buffer is empty, an empty string
    /// (corresponding to `\0`, which has length of 1) is pushed: this means that in case of
    /// success, a strictly positive integer is returned. `is_kern_mem` allows to specify if the
    /// `charbuf_ptr` points to kernel or userspace memory.
    fn push_charbuf(
        &mut self,
        charbuf_ptr: *const c_uchar,
        max_len_to_read: usize,
        is_kern_mem: bool,
    ) -> Result<u16, i64> {
        let pos = Self::data_safe_access(self.payload_pos);
        let limit = pos + max_len_to_read;
        let written_str = if is_kern_mem {
            unsafe { bpf_probe_read_kernel_str_bytes(charbuf_ptr, &mut self.data[pos..limit]) }?
        } else {
            unsafe { bpf_probe_read_user_str_bytes(charbuf_ptr, &mut self.data[pos..limit]) }?
        };
        let written_bytes = written_str.len();
        if written_bytes == 0 {
            // Push '\0' and returns 1 as number of written bytes.
            self.push(0_u8);
            return Ok(1);
        }
        self.payload_pos += written_bytes as u64;
        Ok(written_bytes as u16)
    }

    unsafe fn push_path(
        &mut self,
        path_ptr: *const vmlinux::path,
        max_len_to_read: usize,
    ) -> Result<u16, i64> {
        let path_ptr = path_ptr as *mut aya_ebpf::bindings::path;
        let data_pos = Self::data_safe_access(self.payload_pos);
        let data_ptr = (&mut self.data)
            .as_mut_ptr()
            .cast::<c_char>()
            .byte_add(data_pos);
        let max_len_to_read = max_len_to_read as u32;
        let written_bytes = bpf_d_path(path_ptr, data_ptr, max_len_to_read);
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

    pub fn submit_event(&self) {
        if self.payload_pos > MAX_EVENT_SIZE {
            // TODO: account for drop.
            return;
        }

        let _ = shared_maps::get_events_ringbuf()
            .output(self.data.as_ref(), BPF_RB_FORCE_WAKEUP as u64);
    }
}
