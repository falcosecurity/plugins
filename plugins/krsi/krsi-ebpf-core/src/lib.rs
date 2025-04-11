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

macro_rules! _gen_accessor_no_read {
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

macro_rules! gen_accessors {
    ($parent:ident => { $($variant:ident $name:ident: $type:ty),* $(,)? }) => {
        paste::paste! {
            #[doc = "Represents `*mut " $parent "` with CO-RE relocations."]
            #[repr(transparent)]
            #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
            pub struct [< $parent:camel >] {
                inner: *mut $parent,
            }

            impl [< $parent:camel >] {
                /// # SAFETY
                ///
                /// Must be a valid pointer to struct $type.
                pub unsafe fn new(inner: *mut $parent) -> Self {
                    Self { inner }
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

// /// Returns `file->f_inode`.
// pub fn file_inode(file: *const ffi::file) -> Result<*ffi::inode, i64> {
//     unsafe { bpf_probe_read_kernel(&(*file).f_inode) }
// }
//
// /// Returns `file->f_mode`.
// pub fn file_mode(file: *const vmlinux::file) -> Result<vmlinux::fmode_t, i64> {
//     unsafe { bpf_probe_read_kernel(&(*file).f_mode) }
// }
//
// /// Extract file's private_data field and convert its value to a `* const T`.
// pub fn file_private_data<T>(file: *const vmlinux::file) -> Result<*const T, i64> {
//     unsafe { bpf_probe_read_kernel(&(*file).private_data.cast_const().cast::<T>()) }
// }
//
// /// Returns `file->f_path.dentry`.
// pub fn file_path_dentry(file: *const vmlinux::file) -> Result<*mut vmlinux::dentry, i64> {
//     unsafe { bpf_probe_read_kernel(&(*file).f_path.dentry) }
// }
//
// #[cfg(debug_assertions)]
// pub fn file_name(file: *const vmlinux::file) -> Result<*const c_uchar, i64> {
//     let dentry = unsafe { bpf_probe_read_kernel(&(*file).f_path.dentry) }?;
//     unsafe { bpf_probe_read_kernel(&(*dentry).d_name.name) }
// }
//
// /// Returns `inode->i_sb`.
// pub fn inode_sb(inode: *mut vmlinux::inode) -> Result<*mut vmlinux::super_block, i64> {
//     unsafe { bpf_probe_read_kernel(&(*inode).i_sb) }
// }
//
// /// Returns `inode->i_ino`.
// pub fn inode_ino(inode: *mut vmlinux::inode) -> Result<c_ulong, i64> {
//     unsafe { bpf_probe_read_kernel(&(*inode).i_ino) }
// }
//
// /// Returns `dentry->d_sb`.
// pub fn dentry_sb(dentry: *mut vmlinux::dentry) -> Result<*mut vmlinux::super_block, i64> {
//     unsafe { bpf_probe_read_kernel(&(*dentry).d_sb) }
// }
//
// /// Returns `dentry->d_inode`.
// pub fn dentry_inode(dentry: *mut vmlinux::dentry) -> Result<*mut vmlinux::inode, i64> {
//     unsafe { bpf_probe_read_kernel(&(*dentry).d_inode) }
// }
//
// /// Returns `sb->s_magic`.
// pub fn super_block_magic(sb: *mut vmlinux::super_block) -> Result<core::ffi::c_ulong, i64> {
//     unsafe { bpf_probe_read_kernel(&(*sb).s_magic) }
// }
//
// /// Returns `sb->s_dev`.
// pub fn super_block_dev(sb: *mut vmlinux::super_block) -> Result<vmlinux::dev_t, i64> {
//     unsafe { bpf_probe_read_kernel(&(*sb).s_dev) }
// }
//
// /// Returns `(struct dentry *) ((char *) inode + sizeof(struct inode))`.
// pub fn inode_dentry_ptr(inode: *mut vmlinux::inode) -> Result<*mut vmlinux::dentry, i64> {
//     // We need to compute the size of the inode struct at load time since it can change between
//     // kernel versions
//     // TODO(ekoops): actually we don't know if aya is able to patch the type size and patch is
//     //   in some way; in other words, we don't know if this is the equivalent of doing
//     //   `bpf_core_type_size(struct inode)`.
//     let inode_size = size_of::<vmlinux::inode>();
//     unsafe { bpf_probe_read_kernel(inode.byte_add(inode_size).cast::<*mut vmlinux::dentry>()) }
// }
//
// /// Returns `(char *) filename->name`.
// pub fn filename_name(filename: *const vmlinux::filename) -> Result<*const c_uchar, i64> {
//     let ptr = unsafe { &raw const (*filename).name }.cast::<*const c_uchar>();
//     unsafe { bpf_probe_read_kernel(ptr) }
// }

// gen_accessors!(file => {
//     no_read_wrapped f_path: Path,
// });
// gen_accessors!(path => {
//     wrapper dentry: Dentry,
//     wrapper mnt: Vfsmount,
// });
// gen_accessors!(dentry => {
//     no_read_wrapped d_name: Qstr,
//     wrapper d_parent: Dentry,
// });
// gen_accessors!(vfsmount => {
//     no_read_container mnt: Mount,
//     wrapper mnt_root: Dentry,
// });
//
// gen_accessors!(qstr => {
//     plain len: u32,
//     plain name: *const u8,
// });
// gen_accessors!(mount => {
//     wrapper mnt_parent: Mount,
//     wrapper mnt_mountpoint: Dentry,
//     no_read_wrapped mnt: Vfsmount,
// });
//
// gen_accessors!(files_struct => {
//     plain count: atomic_t,
//     wrapper fdt: Fdtable,
// });
//
// gen_accessors!(fdtable => {
//     plain max_fds: u32,
//     no_read fd: *mut *mut *mut file,
//     plain open_fds: *mut u64,
// });
//
// gen_accessors!(art_heap => {
//     no_read target_footprint: *mut u64,
//     no_read num_bytes_allocated: *mut u64,
//     no_read gc_cause: *mut u32,
//     no_read duration_ns: *mut u64,
//     no_read freed_objects: *mut u64,
//     no_read freed_bytes: *mut u64,
//     no_read freed_los_objects: *mut u64,
//     no_read freed_los_bytes: *mut u64,
//     no_read gcs_completed: *mut u32,
//     no_read pause_times_begin: *mut u64,
//     no_read pause_times_end: *mut u64,
// });
