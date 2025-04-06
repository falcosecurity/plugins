use core::ffi::c_uchar;

use aya_ebpf::{
    cty::{c_uint, c_ulong},
    helpers::bpf_probe_read_kernel,
};

use crate::vmlinux;

/// Returns `file->f_flags`.
pub fn file_flags(file: *const vmlinux::file) -> Result<c_uint, i64> {
    unsafe { bpf_probe_read_kernel(&(*file).f_flags) }
}

/// Returns `file->f_inode`.
pub fn file_inode(file: *const vmlinux::file) -> Result<*mut vmlinux::inode, i64> {
    unsafe { bpf_probe_read_kernel(&(*file).f_inode) }
}

/// Returns `file->f_mode`.
pub fn file_mode(file: *const vmlinux::file) -> Result<vmlinux::fmode_t, i64> {
    unsafe { bpf_probe_read_kernel(&(*file).f_mode) }
}

/// Extract file's private_data field and convert its value to a `* const T`.
pub fn file_private_data<T>(file: *const vmlinux::file) -> Result<*const T, i64> {
    unsafe { bpf_probe_read_kernel(&(*file).private_data.cast_const().cast::<T>()) }
}

/// Returns `file->f_path.dentry`.
pub fn file_path_dentry(file: *const vmlinux::file) -> Result<*mut vmlinux::dentry, i64> {
    unsafe { bpf_probe_read_kernel(&(*file).f_path.dentry) }
}

#[cfg(debug_assertions)]
pub fn file_name(file: *const vmlinux::file) -> Result<*const c_uchar, i64> {
    let dentry = unsafe { bpf_probe_read_kernel(&(*file).f_path.dentry) }?;
    unsafe { bpf_probe_read_kernel(&(*dentry).d_name.name) }
}

/// Returns `inode->i_sb`.
pub fn inode_sb(inode: *mut vmlinux::inode) -> Result<*mut vmlinux::super_block, i64> {
    unsafe { bpf_probe_read_kernel(&(*inode).i_sb) }
}

/// Returns `inode->i_ino`.
pub fn inode_ino(inode: *mut vmlinux::inode) -> Result<c_ulong, i64> {
    unsafe { bpf_probe_read_kernel(&(*inode).i_ino) }
}

/// Returns `dentry->d_sb`.
pub fn dentry_sb(dentry: *mut vmlinux::dentry) -> Result<*mut vmlinux::super_block, i64> {
    unsafe { bpf_probe_read_kernel(&(*dentry).d_sb) }
}

/// Returns `dentry->d_inode`.
pub fn dentry_inode(dentry: *mut vmlinux::dentry) -> Result<*mut vmlinux::inode, i64> {
    unsafe { bpf_probe_read_kernel(&(*dentry).d_inode) }
}

/// Returns `sb->s_magic`.
pub fn super_block_magic(sb: *mut vmlinux::super_block) -> Result<core::ffi::c_ulong, i64> {
    unsafe { bpf_probe_read_kernel(&(*sb).s_magic) }
}

/// Returns `sb->s_dev`.
pub fn super_block_dev(sb: *mut vmlinux::super_block) -> Result<vmlinux::dev_t, i64> {
    unsafe { bpf_probe_read_kernel(&(*sb).s_dev) }
}

/// Returns `(struct dentry *) ((char *) inode + sizeof(struct inode))`.
pub fn inode_dentry_ptr(inode: *mut vmlinux::inode) -> Result<*mut vmlinux::dentry, i64> {
    // We need to compute the size of the inode struct at load time since it can change between
    // kernel versions
    // TODO(ekoops): actually we don't know if aya is able to patch the type size and patch is
    //   in some way; in other words, we don't know if this is the equivalent of doing
    //   `bpf_core_type_size(struct inode)`.
    let inode_size = size_of::<vmlinux::inode>();
    unsafe { bpf_probe_read_kernel(inode.byte_add(inode_size).cast::<*mut vmlinux::dentry>()) }
}

/// Returns `(char *) filename->name`.
pub fn filename_name(filename: *const vmlinux::filename) -> Result<*const c_uchar, i64> {
    let ptr = unsafe { &raw const (*filename).name }.cast::<*const c_uchar>();
    unsafe { bpf_probe_read_kernel(ptr) }
}
