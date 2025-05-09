// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use core::ptr::null_mut;

use aya_ebpf::{
    bindings::BPF_RB_FORCE_WAKEUP,
    cty::c_uchar,
    helpers::{
        bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, bpf_probe_read_kernel_str_bytes,
        bpf_probe_read_user_str_bytes,
    },
};
use krsi_common::{EventHeader, EventType};
use krsi_ebpf_core::{
    read_field, Filename, Path, Sock, Sockaddr, SockaddrIn, SockaddrIn6, SockaddrUn, Socket, Wrap,
};

use crate::{defs, get_event_num_params, scap, shared_state, sockets, FileDescriptor};

// Event maximum size.
const MAX_EVENT_SIZE: u64 = 8 * 1024;

// Parameter maximum size.
const MAX_PARAM_SIZE: u64 = MAX_EVENT_SIZE - 1;

const AUXILIARY_BUFFER_SIZE: usize = 16 * 1024;

pub struct AuxiliaryBuffer {
    // raw space to save our variable-size event.
    pub data: [u8; AUXILIARY_BUFFER_SIZE],
    // position of the first empty byte in the `data` buffer.
    pub payload_pos: u64,
    // position of the first empty slot into the lengths array of the event.
    pub lengths_pos: u8,
    // event type we want to send to userspace.
    pub event_type: u16,
}

impl AuxiliaryBuffer {
    fn event_header_mut(&mut self) -> &mut EventHeader {
        unsafe { &mut *self.data.as_mut_ptr().cast::<EventHeader>() }
    }

    pub fn preload_event_header(&mut self, event_type: EventType) {
        let evt_hdr = self.event_header_mut();
        let nparams = get_event_num_params(event_type);
        evt_hdr.nparams = nparams as u32;
        evt_hdr.ts = shared_state::boot_time() + unsafe { bpf_ktime_get_boot_ns() };
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
        self.write_value(param);
        self.write_len(size_of::<T>() as u16);
    }

    pub fn store_empty_param(&mut self) {
        self.write_len(0);
    }

    /// This helper stores the charbuf pointed by `charbuf` into the auxbuf. We read until we find
    /// a `\0`, if the charbuf length is greater than `max_len_to_read`, we read up to
    /// `max_len_to_read-1` bytes and add the `\0`. `is_kern_mem` allows to specify if the `charbuf`
    /// points to kernel or userspace memory. In case of error, the auxbuf is left untouched.
    pub unsafe fn store_charbuf_param(
        &mut self,
        charbuf: *const c_uchar,
        max_len_to_read: u16,
        is_kern_mem: bool,
    ) -> Result<u16, i64> {
        let mut charbuf_len = 0_u16;
        if !charbuf.is_null() {
            charbuf_len = self.write_charbuf(charbuf, max_len_to_read as usize, is_kern_mem)?;
        }
        self.write_len(charbuf_len);
        Ok(charbuf_len)
    }

    /// This helper stores the path pointed by `path` into the auxbuf. We read until we find a `\0`,
    /// if the path length is greater than `max_len_to_read`, we read up to `max_len_to_read-1`
    /// bytes and add the `\0`.
    pub unsafe fn store_path_param(
        &mut self,
        path: &Path,
        max_len_to_read: u16,
    ) -> Result<u16, i64> {
        let mut path_len = 0_u16;
        if !path.is_null() {
            path_len = self.write_path(&path, max_len_to_read as usize)?;
        }
        self.write_len(path_len);
        Ok(path_len)
    }

    pub fn store_sockaddr_param(&mut self, sockaddr: &Sockaddr, is_kern_sockaddr: bool) {
        let sa_family = read_field!(sockaddr => sa_family, is_kern_sockaddr);
        let Ok(sa_family) = sa_family else {
            self.store_empty_param();
            return;
        };

        let final_parameter_len = match sa_family {
            defs::AF_INET => self.write_inet_sockaddr(&sockaddr.as_sockaddr_in(), is_kern_sockaddr),
            defs::AF_INET6 => {
                self.write_inet6_sockaddr(&sockaddr.as_sockaddr_in6(), is_kern_sockaddr)
            }
            defs::AF_UNIX => self.write_unix_sockaddr(&sockaddr.as_sockaddr_un(), is_kern_sockaddr),
            _ => 0,
        } as u16;

        self.write_len(final_parameter_len);
    }

    fn write_inet_sockaddr(&mut self, sockaddr: &SockaddrIn, is_kern_sockaddr: bool) -> usize {
        let addr = sockaddr.sin_addr();
        let ipv4_addr = read_field!(addr => s_addr, is_kern_sockaddr).unwrap_or(0);
        let port = read_field!(sockaddr => sin_port, is_kern_sockaddr).unwrap_or(0);
        self.write_value(scap::encode_socket_family(defs::AF_INET));
        self.write_value(ipv4_addr);
        self.write_value(u16::from_be(port));
        defs::FAMILY_SIZE + defs::IPV4_SIZE + defs::PORT_SIZE
    }

    fn write_inet6_sockaddr(&mut self, sockaddr: &SockaddrIn6, is_kern_sockaddr: bool) -> usize {
        let addr = sockaddr.sin6_addr();
        let ipv6_addr = read_field!(addr => in6_u, is_kern_sockaddr).unwrap_or([0, 0, 0, 0]);
        let port = read_field!(sockaddr => sin6_port, is_kern_sockaddr).unwrap_or(0);
        self.write_value(scap::encode_socket_family(defs::AF_INET6));
        self.write_value(ipv6_addr);
        self.write_value(u16::from_be(port));
        defs::FAMILY_SIZE + defs::IPV6_SIZE + defs::PORT_SIZE
    }

    fn write_unix_sockaddr(&mut self, sockaddr: &SockaddrUn, is_kern_sockaddr: bool) -> usize {
        let mut path: [c_uchar; defs::UNIX_PATH_MAX] = [0; defs::UNIX_PATH_MAX];
        let _ = sockets::sockaddr_un_path_into(&sockaddr, is_kern_sockaddr, &mut path);
        self.write_value(scap::encode_socket_family(defs::AF_UNIX));
        let written_bytes = self.write_sockaddr_path(&mut path).unwrap_or(0);
        defs::FAMILY_SIZE + written_bytes as usize
    }

    /// Store the socktuple obtained by extracting information from the provided socket and the
    /// provided sockaddr. Returns the stored lengths.
    pub fn store_sock_tuple_param(
        &mut self,
        sock: &Socket,
        is_outbound: bool,
        sockaddr: &Sockaddr,
        is_kern_sockaddr: bool,
    ) -> u16 {
        if sock.is_null() {
            self.store_empty_param();
            return 0;
        }

        let Ok(sk) = sock.sk() else {
            self.store_empty_param();
            return 0;
        };

        let Ok(sk_family) = sk.__sk_common().skc_family() else {
            self.store_empty_param();
            return 0;
        };

        let final_parameter_len = match sk_family {
            defs::AF_INET => {
                self.write_inet_sock_tuple(&sk, is_outbound, sockaddr, is_kern_sockaddr)
            }
            defs::AF_INET6 => {
                self.write_inet6_sock_tuple(&sk, is_outbound, sockaddr, is_kern_sockaddr)
            }
            defs::AF_UNIX => {
                self.write_unix_sock_tuple(&sk, is_outbound, sockaddr, is_kern_sockaddr)
            }
            _ => 0,
        } as u16;

        self.write_len(final_parameter_len);
        final_parameter_len
    }

    fn write_inet_sock_tuple(
        &mut self,
        sk: &Sock,
        is_outbound: bool,
        sockaddr: &Sockaddr,
        is_kern_sockaddr: bool,
    ) -> usize {
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

        // Pack the tuple info: (sock_family, local_ipv4, local_port, remote_ipv4, remote_port)
        self.write_value(scap::encode_socket_family(defs::AF_INET));
        if is_outbound {
            self.write_value(ipv4_local);
            self.write_value(u16::from_be(port_local));
            self.write_value(ipv4_remote);
            self.write_value(u16::from_be(port_remote));
        } else {
            self.write_value(ipv4_remote);
            self.write_value(u16::from_be(port_remote));
            self.write_value(ipv4_local);
            self.write_value(u16::from_be(port_local));
        }

        defs::FAMILY_SIZE + defs::IPV4_SIZE + defs::PORT_SIZE + defs::IPV4_SIZE + defs::PORT_SIZE
    }

    fn write_inet6_sock_tuple(
        &mut self,
        sk: &Sock,
        is_outbound: bool,
        sockaddr: &Sockaddr,
        is_kern_sockaddr: bool,
    ) -> usize {
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

        // Pack the tuple info: (sock_family, local_ipv6, local_port, remote_ipv6, remote_port)
        self.write_value(scap::encode_socket_family(defs::AF_INET6));
        if is_outbound {
            self.write_value(ipv6_local);
            self.write_value(u16::from_be(port_local));
            self.write_value(ipv6_remote);
            self.write_value(u16::from_be(port_remote));
        } else {
            self.write_value(ipv6_remote);
            self.write_value(u16::from_be(port_remote));
            self.write_value(ipv6_local);
            self.write_value(u16::from_be(port_local));
        }

        defs::FAMILY_SIZE + defs::IPV6_SIZE + defs::PORT_SIZE + defs::IPV6_SIZE + defs::PORT_SIZE
    }

    fn write_unix_sock_tuple(
        &mut self,
        sk: &Sock,
        is_outbound: bool,
        sockaddr: &Sockaddr,
        is_kern_sockaddr: bool,
    ) -> usize {
        let sk_local = sk.as_unix_sock();

        let sk_peer = sk_local.peer().unwrap_or(Sock::wrap(null_mut()));
        let sk_peer = sk_peer.as_unix_sock();

        let mut path: [c_uchar; defs::UNIX_PATH_MAX] = [0; defs::UNIX_PATH_MAX];
        let path_mut = &mut path;

        // Pack the tuple info: (sock_family, dest_os_ptr, src_os_ptr, dest_unix_path)
        self.write_value(scap::encode_socket_family(defs::AF_UNIX));
        if is_outbound {
            self.write_value(sk_peer.serialize_ptr() as u64);
            self.write_value(sk_local.serialize_ptr() as u64);
            if sk_peer.is_null() && !sockaddr.is_null() {
                let sockaddr = sockaddr.as_sockaddr_un();
                let _ = sockets::sockaddr_un_path_into(&sockaddr, is_kern_sockaddr, path_mut);
            } else if !sk_peer.is_null() {
                let _ = sockets::unix_sock_addr_path_into(&sk_peer, path_mut);
            }
        } else {
            self.write_value(sk_local.serialize_ptr() as u64);
            self.write_value(sk_peer.serialize_ptr() as u64);
            let _ = sockets::unix_sock_addr_path_into(&sk_local, path_mut);
        }

        let written_bytes = self.write_sockaddr_path(&path).unwrap_or(0);

        defs::FAMILY_SIZE + defs::KERNEL_POINTER + defs::KERNEL_POINTER + written_bytes as usize
    }

    fn write_sockaddr_path(&mut self, path: &[c_uchar; defs::UNIX_PATH_MAX]) -> Result<u16, i64> {
        // Notice an exception in `sun_path` (https://man7.org/linux/man-pages/man7/unix.7.html):
        // an `abstract socket address` is distinguished (from a pathname socket) by the fact that
        // sun_path[0] is a null byte (`\0`). So in this case, we need to skip the initial `\0`.
        //
        // Warning: if you try to extract the path slice in a separate statement as follows, the
        // verifier will complain (maybe because it would lose information about slice length):
        // let path_ref = if path[0] == 0 {&path[1..]} else {&path[..]};
        if path[0] == 0 {
            let path_ref = &path[1..];
            self.write_charbuf(path_ref.as_ptr().cast(), path.len(), true)
        } else {
            let path_ref = &path[..];
            self.write_charbuf(path_ref.as_ptr().cast(), path.len(), true)
        }
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

    fn write_value<T>(&mut self, value: T)
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

    fn write_len(&mut self, value: u16) {
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
    fn write_charbuf(
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

    fn write_path(&mut self, path: &Path, max_len_to_read: usize) -> Result<u16, i64> {
        let data_pos = Self::data_safe_access(self.payload_pos);
        let data = &mut self.data[data_pos..];
        let written_bytes = unsafe { path.read_into(data, max_len_to_read as u32)? };
        if written_bytes == 0 {
            // Push '\0' (empty string) and returns 1 as number of written bytes.
            self.write_value(0_u8);
            return Ok(1);
        }
        self.payload_pos += written_bytes as u64;
        Ok(written_bytes as u16)
    }

    pub fn store_filename_param(
        &mut self,
        filename: &Filename,
        max_len_to_read: u16,
        is_kern_mem: bool,
    ) {
        if let Err(_) = filename.name().and_then(|name| unsafe {
            self.store_charbuf_param(name.cast(), max_len_to_read, is_kern_mem)
        }) {
            self.store_empty_param();
        }
    }

    pub fn submit_event(&self) {
        if self.payload_pos > MAX_EVENT_SIZE {
            // TODO: account for drop.
            return;
        }

        let evt = &self.data.as_ref()[..self.payload_pos as usize];
        let _ = shared_state::events_ringbuf().output(evt, BPF_RB_FORCE_WAKEUP as u64);
    }
}
