use krsi_ebpf_core::{Dentry, File, Inode, Wrap};

use crate::{
    files::{dev, extractors, Overlay, OVERLAYFS_SUPER_MAGIC},
    vmlinux,
};

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
        .and_then(|inode| extractors::inode_dentry_ptr(inode.cast()))
        .and_then(|dentry| unsafe { Dentry::wrap(dentry.cast()) }.d_inode())
        .and_then(|inode| unsafe { Inode::wrap(inode.cast()) }.i_ino())
    {
        Ok(_) => Overlay::Upper,
        Err(_) => Overlay::Lower,
    }
}
