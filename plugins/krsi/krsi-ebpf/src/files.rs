use crate::vmlinux;

mod dev;
pub mod extract;

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

pub fn get_dev_ino_overlay(
    file: *const vmlinux::file,
) -> Result<(vmlinux::dev_t, u64, Overlay), i64> {
    let inode = extract::file_inode(file)?;
    let sb = extract::inode_sb(inode)?;
    let dev = extract::super_block_dev(sb)?;
    let ino = extract::inode_ino(inode)?;
    Ok((dev::encode(dev), ino, get_overlay_layer(file)))
}

fn get_overlay_layer(file: *const vmlinux::file) -> Overlay {
    let Ok(dentry) = extract::file_path_dentry(file) else {
        return Overlay::None;
    };

    if !extract::dentry_sb(dentry)
        .and_then(extract::super_block_magic)
        .is_ok_and(|sb_magic| sb_magic == OVERLAYFS_SUPER_MAGIC)
    {
        return Overlay::None;
    }

    match extract::dentry_inode(dentry)
        .and_then(extract::inode_dentry_ptr)
        .and_then(extract::dentry_inode)
        .and_then(extract::inode_ino)
    {
        Ok(_) => Overlay::Upper,
        Err(_) => Overlay::Lower,
    }
}
