use crate::{
    files::{dev, extractors, Overlay, OVERLAYFS_SUPER_MAGIC},
    vmlinux,
};

pub fn dev_ino_overlay(file: *const vmlinux::file) -> Result<(vmlinux::dev_t, u64, Overlay), i64> {
    let inode = extractors::file_inode(file)?;
    let sb = extractors::inode_sb(inode)?;
    let dev = extractors::super_block_dev(sb)?;
    let ino = extractors::inode_ino(inode)?;
    Ok((dev::encode(dev), ino, overlay(file)))
}

fn overlay(file: *const vmlinux::file) -> Overlay {
    let Ok(dentry) = extractors::file_path_dentry(file) else {
        return Overlay::None;
    };

    if !extractors::dentry_sb(dentry)
        .and_then(extractors::super_block_magic)
        .is_ok_and(|sb_magic| sb_magic == OVERLAYFS_SUPER_MAGIC)
    {
        return Overlay::None;
    }

    match extractors::dentry_inode(dentry)
        .and_then(extractors::inode_dentry_ptr)
        .and_then(extractors::dentry_inode)
        .and_then(extractors::inode_ino)
    {
        Ok(_) => Overlay::Upper,
        Err(_) => Overlay::Lower,
    }
}
