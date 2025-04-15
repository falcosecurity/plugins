use core::ffi::c_uchar;

use aya_ebpf::helpers::bpf_probe_read_kernel;

use crate::vmlinux;

/// Extract file's private_data field and convert its value to a `* const T`.
pub fn file_private_data<T>(file: *const vmlinux::file) -> Result<*const T, i64> {
    unsafe { bpf_probe_read_kernel(&(*file).private_data.cast_const().cast::<T>()) }
}

#[cfg(debug_assertions)]
pub fn file_name(file: *const vmlinux::file) -> Result<*const c_uchar, i64> {
    let dentry = unsafe { bpf_probe_read_kernel(&(*file).f_path.dentry) }?;
    unsafe { bpf_probe_read_kernel(&(*dentry).d_name.name) }
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
