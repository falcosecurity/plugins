use krsi_ebpf_core::{ffi, File};

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

pub fn dev_ino_overlay(file: &File) -> Result<(ffi::dev_t, u64, Overlay), i64> {
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

    match dentry
        .d_inode()
        .and_then(|inode| inode.upper_dentry())
        .and_then(|dentry| dentry.d_inode())
        .and_then(|inode| inode.i_ino())
    {
        Ok(_) => Overlay::Upper,
        Err(_) => Overlay::Lower,
    }
}
