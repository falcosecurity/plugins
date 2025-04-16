use aya_ebpf::helpers::bpf_probe_read_kernel;
use krsi_ebpf_core::{Dentry, File, Inode, Wrap};

use crate::vmlinux;

mod dev;

const OVERLAYFS_SUPER_MAGIC: u64 = 0x794c7630;

pub enum Overlay {
    None = 0,
    Upper,
    Lower,
}

impl TryFrom<u16> for Overlay {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == Overlay::None as u16 => Ok(Overlay::None),
            x if x == Overlay::Upper as u16 => Ok(Overlay::Upper),
            x if x == Overlay::Lower as u16 => Ok(Overlay::Lower),
            _ => Err(()),
        }
    }
}

pub fn dev_ino_overlay(file: &File) -> Result<(vmlinux::dev_t, u64, Overlay), i64> {
    let inode = file.f_inode()?;
    let sb = inode.i_sb()?;
    let dev = sb.s_dev()?;
    let ino = inode.i_ino()?;
    Ok((dev::encode(dev), ino, overlay(file)))
}

fn overlay(file: &File) -> Overlay {
    let Ok(dentry) = file.f_path().dentry() else {
        return Overlay::None;
    };

    if !dentry
        .d_sb()
        .and_then(|sb| sb.s_magic())
        .is_ok_and(|s_magic| s_magic == OVERLAYFS_SUPER_MAGIC)
    {
        return Overlay::None;
    }

    // TODO(ekoops): the following alternates CO-RE and non CO-RE operation due to d_inode() being
    //   forced to interact with inode_dentry_ptr. We still use the non CO-RE inode_dentry_ptr
    //   operation because I still haven't found a way to implement it using a CO-RE approach (see
    //   `core_helpers.h` for more details).
    match dentry
        .d_inode()
        .and_then(|inode| inode_dentry_ptr(inode.cast()))
        .and_then(|dentry| unsafe { Dentry::wrap(dentry.cast()) }.d_inode())
        .and_then(|inode| unsafe { Inode::wrap(inode.cast()) }.i_ino())
    {
        Ok(_) => Overlay::Upper,
        Err(_) => Overlay::Lower,
    }
}

/// Returns `(struct dentry *) ((char *) inode + sizeof(struct inode))`.
fn inode_dentry_ptr(inode: *mut vmlinux::inode) -> Result<*mut vmlinux::dentry, i64> {
    // We need to compute the size of the inode struct at load time since it can change between
    // kernel versions
    // TODO(ekoops): actually we don't know if aya is able to patch the type size and patch is
    //   in some way; in other words, we don't know if this is the equivalent of doing
    //   `bpf_core_type_size(struct inode)`.
    let inode_size = size_of::<vmlinux::inode>();
    unsafe { bpf_probe_read_kernel(inode.byte_add(inode_size).cast::<*mut vmlinux::dentry>()) }
}
