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

#![no_std]
#![allow(clippy::len_without_is_empty)]

#[inline]
fn bpf_probe_read_kernel<T>(ptr: *const T) -> Result<T, i64> {
    #[cfg(target_arch = "bpf")]
    unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(ptr)
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        Ok(core::ptr::read(ptr))
    }
}

#[inline]
fn bpf_probe_read_user<T>(ptr: *const T) -> Result<T, i64> {
    #[cfg(target_arch = "bpf")]
    unsafe {
        aya_ebpf::helpers::bpf_probe_read_user(ptr)
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        Ok(core::ptr::read(ptr))
    }
}

pub mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    #[repr(C, packed)]
    #[allow(non_camel_case_types)]
    pub struct qstr {
        pub hash: u32,
        pub len: u32,
        pub name: *const u8,
    }

    include!(concat!(env!("OUT_DIR"), "/core_helpers.rs"));
}

use core::ffi::c_void;

use aya_ebpf::helpers::bpf_d_path;
use ffi::*;

macro_rules! gen_accessor_plain {
    ($parent:ident => $name:ident, $type:ty) => {
        paste::paste! {
            #[doc = "Reads the value of the field `" $parent "." $name "` with CO-RE relocations."]
            #[inline(always)]
            pub fn $name(&self) -> Result<$type, i64> {
                unsafe { bpf_probe_read_kernel([< $parent _ $name >](self.inner) as *const _) }
            }

            #[doc = "Reads the value of the field `" $parent "." $name "` with CO-RE relocations (user memory variant)."]
            #[inline(always)]
            pub fn [< $name _user >](&self) -> Result<$type, i64> {
                unsafe { bpf_probe_read_user([< $parent _ $name >](self.inner) as *const _) }
            }
        }
    };
}

macro_rules! gen_accessor_wrapper {
    ($parent:ident => $name:ident, $type:ident) => {
        paste::paste! {
            #[doc = "Reads the value of the field `" $parent "." $name "` with CO-RE relocations."]
            #[inline(always)]
            pub fn $name(&self) -> Result<$type, i64> {
                Ok($type { inner: unsafe { bpf_probe_read_kernel([< $parent _ $name >](self.inner) as *const _) }? })
            }

            #[doc = "Reads the value of the field `" $parent "." $name "` with CO-RE relocations (user memory variant)."]
            #[inline(always)]
            pub fn [< $name _user >](&self) -> Result<$type, i64> {
                Ok($type { inner: unsafe { bpf_probe_read_user([< $parent _ $name >](self.inner) as *const _) }? })
            }
        }
    };
}

macro_rules! gen_accessor_no_read_wrapped {
    ($parent:ident => $name:ident, $type:ident) => {
        paste::paste! {
            #[doc = "Reads the value of the field `" $parent "." $name "` with CO-RE relocations."]
            #[inline(always)]
            pub fn $name(&self) -> $type {
                unsafe { $type { inner: [< $parent _ $name >](self.inner) } }
            }
        }
    };
}

macro_rules! gen_accessor_no_read {
    ($parent:ident => $name:ident, $type:ty) => {
        paste::paste! {
            #[doc = "Reads the value of the field `" $parent "." $name "` with CO-RE relocations."]
            #[inline(always)]
            pub fn $name(&self) -> $type {
                unsafe { [< $parent _ $name >](self.inner) }
            }
        }
    };
}

macro_rules! _gen_accessor_no_read_container {
    ($parent:ident => $name:ident, $type:ident) => {
        paste::paste! {
            #[inline(always)]
            pub fn container(&self) -> $type {
                unsafe { $type { inner: [< $parent _ container >](self.inner) } }
            }
        }
    };
}

macro_rules! gen_accessor {
    (plain: $parent:ident => $name:ident, $type:ty) => {
        gen_accessor_plain!($parent => $name, $type);
    };
    (wrapper: $parent:ident => $name:ident, $type:ty) => {
        paste::paste! {
            gen_accessor_wrapper!($parent => $name, [< $type >]);
        }
    };
    (no_read: $parent:ident => $name:ident, $type:ty) => {
        paste::paste! {
            gen_accessor_no_read!($parent => $name, $type);
        }
    };
    (no_read_wrapped: $parent:ident => $name:ident, $type:ty) => {
        paste::paste! {
            gen_accessor_no_read_wrapped!($parent => $name, [< $type >]);
        }
    };
    (no_read_container: $parent:ident => $name:ident, $type:ty) => {
        paste::paste! {
            gen_accessor_no_read_container!($parent => $name, [< $type >]);
        }
    };
}

pub trait Wrap {
    type RawType;
    fn wrap(arg: *mut Self::RawType) -> Self;
}

pub fn wrap_arg<T: Wrap>(arg: usize) -> T {
    T::wrap(arg as *mut _)
}

#[macro_export]
macro_rules! read_field {
    ($parent:ident => $name:ident, $is_kern_mem:expr) => {
        paste::paste! {
            if $is_kern_mem {
                $parent.$name()
            } else {
                $parent.[< $name _user >]()
            }
        }
    };
}

macro_rules! gen_accessors {
    ($parent:ident => { $($variant:ident $name:ident: $type:ty),* $(,)? }) => {
        paste::paste! {
            #[doc = "Represents `*mut " $parent "` with CO-RE relocations."]
            #[repr(transparent)]
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            pub struct [< $parent:camel >] {
                inner: *mut $parent,
            }

            impl Wrap for [< $parent:camel >] {
                type RawType = $parent;
                #[inline(always)]
                fn wrap(inner: *mut Self::RawType) -> Self {
                    Self { inner }
                }
            }

            impl [< $parent:camel >] {
                #[inline(always)]
                pub fn is_null(&self) -> bool {
                    false
                    // self.inner.is_null()
                }

                /// Returns a serialized representation of the inner pointer.
                #[inline(always)]
                pub fn serialize_ptr(&self) -> usize {
                    self.inner as usize
                }

                $(
                    gen_accessor!($variant: $parent => $name, $type);
                )*
            }
        }
    };
}

gen_accessors!(super_block => {
    plain s_dev: u32,
    plain s_magic: u64,
});

gen_accessors!(inode => {
    wrapper i_sb: SuperBlock,
    plain i_ino: u64,
    wrapper upper_dentry: Dentry,
});

gen_accessors!(dentry => {
    wrapper d_inode: Inode,
    wrapper d_sb: SuperBlock,
});

gen_accessors!(path => {
    wrapper dentry: Dentry,
});

impl Path {
    pub unsafe fn read_into(&self, buf: &mut [u8], max_len_to_read: u32) -> Result<usize, i64> {
        let buf = buf.as_mut_ptr().cast();
        let written_bytes = bpf_d_path(self.inner.cast(), buf, max_len_to_read);
        if written_bytes < 0 {
            Err(written_bytes)
        } else {
            Ok(written_bytes as usize)
        }
    }
}

gen_accessors!(file => {
    plain f_mode: u32,
    plain private_data: * mut c_void,
    plain f_flags: u32,
    wrapper f_inode: Inode,
    no_read_wrapped f_path: Path,
    // plain arg_end: u64,
    // wrapper exe_file: File,
});

gen_accessors!(in6_addr => {
    plain in6_u: [u32; 4],
});

gen_accessors!(sock_common => {
    plain skc_daddr: u32,
    plain skc_family: u16,
    plain skc_dport: u16,
    no_read_wrapped skc_v6_daddr: In6Addr,
});

gen_accessors!(sock => {
    no_read_wrapped __sk_common: SockCommon,
});

gen_accessors!(socket => {
    wrapper sk: Sock,
});

gen_accessors!(ipv6_pinfo => {
    no_read_wrapped saddr: In6Addr,
});

gen_accessors!(inet_sock => {
    wrapper pinet6: Ipv6Pinfo,
    plain inet_saddr: u32,
    plain inet_sport: u16,
});

gen_accessors!(in_addr => {
    plain s_addr: u32
});

gen_accessors!(sockaddr_in => {
    plain sin_port: u16,
    no_read_wrapped sin_addr: InAddr,
});

gen_accessors!(sockaddr_in6 => {
    plain sin6_port: u16,
    no_read_wrapped sin6_addr: In6Addr,
});

gen_accessors!(sockaddr_un => {
    no_read sun_path: *mut [i8; 108] // TODO(ekoops): use UNIX_PATH_MAX (108).
});

gen_accessors!(unix_address => {
    plain len: i32,
    no_read name: * mut [sockaddr_un; 0], // TODO(ekoops): handle flexible arrays.
});

gen_accessors!(sockaddr => {
    plain sa_family: u16,
});

impl Sockaddr {
    #[inline(always)]
    pub fn as_sockaddr_in(&self) -> SockaddrIn {
        SockaddrIn {
            inner: self.inner.cast::<sockaddr_in>(),
        }
    }

    #[inline(always)]
    pub fn as_sockaddr_in6(&self) -> SockaddrIn6 {
        SockaddrIn6 {
            inner: self.inner.cast::<sockaddr_in6>(),
        }
    }

    #[inline(always)]
    pub fn as_sockaddr_un(&self) -> SockaddrUn {
        SockaddrUn {
            inner: self.inner.cast::<sockaddr_un>(),
        }
    }
}

gen_accessors!(unix_sock => {
    wrapper addr: UnixAddress,
    wrapper peer: Sock
});

impl Sock {
    #[inline(always)]
    pub fn as_inet_sock(&self) -> InetSock {
        InetSock {
            inner: self.inner.cast::<inet_sock>(),
        }
    }

    #[inline(always)]
    pub fn as_unix_sock(&self) -> UnixSock {
        UnixSock {
            inner: self.inner.cast::<unix_sock>(),
        }
    }
}

gen_accessors!(filename => {
    plain name: * mut char,
});

gen_accessors!(io_cqe => {
    plain res: i32,
    plain fd: i32,
});

gen_accessors!(io_async_msghdr => {
    no_read_wrapped addr: Sockaddr,
});

gen_accessors!(io_kiocb => {
    wrapper file: File,
    no_read cmd: * mut io_cmd_data,
    plain flags: u64,
    no_read_wrapped cqe: IoCqe,
    plain async_data: * mut c_void,
});

impl IoKiocb {
    pub fn cmd_as<T: Wrap>(&self) -> T {
        T::wrap(self.cmd() as *mut _)
    }

    pub fn async_data_as<T: Wrap>(&self) -> Result<T, i64> {
        Ok(T::wrap(self.async_data()? as *mut _))
    }
}

gen_accessors!(io_rename => {
    plain old_dfd: i32,
    plain new_dfd: i32,
    wrapper oldpath: Filename,
    wrapper newpath: Filename,
    plain flags: i32
});

gen_accessors!(io_unlink => {
    plain dfd: i32,
    plain flags: i32,
    wrapper filename: Filename,
});

gen_accessors!(io_socket => {
    plain domain: i32,
    plain r#type: i32,
    plain protocol: i32,
    plain flags: i32,
    plain file_slot: u32,
});

gen_accessors!(io_bind => {
    plain addr_len: i32,
});
