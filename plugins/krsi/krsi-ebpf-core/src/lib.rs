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

// gen_accessors!(file => {
//     wrapper mm: MmStruct,
//     plain pid: u32,
//     plain tgid: u32,
//     plain start_time: u64,
//     wrapper real_parent: TaskStruct,
//     wrapper group_leader: TaskStruct,
//     wrapper files: FilesStruct,
//     no_read comm: *mut [i8; 16],
// });

gen_accessors!(super_block => {
    plain s_dev: u32,
    plain s_magic: u64,
});

gen_accessors!(inode => {
    wrapper i_sb: SuperBlock,
    plain i_ino: u64,
});

gen_accessors!(dentry => {
    // TODO(ekoops): use `wrapper` instead of `plain` for `d_inode` once we fix the `core_helpers.h`
    //   problem related to clang not recognizing `__builtin_preserve_type_info`.
    plain d_inode: * mut Inode,
    wrapper d_sb: SuperBlock,
});

gen_accessors!(path => {
    wrapper dentry: Dentry,
});

gen_accessors!(file => {
    plain f_mode: u32,
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

gen_accessors!(sockaddr => {});

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
