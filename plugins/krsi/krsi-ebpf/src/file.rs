use crate::vmlinux;
use aya_ebpf::helpers::bpf_probe_read_kernel;
use krsi_common::EventType;

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

pub unsafe fn extract_dev_ino_overlay(
    file: *const vmlinux::file,
    dev: &mut vmlinux::dev_t,
    ino: &mut u64,
    overlay: &mut Overlay,
) -> Result<(), i64> {
    let inode_ptr = bpf_probe_read_kernel(&(*file).f_inode)?;
    let sb_ptr = bpf_probe_read_kernel(&(*inode_ptr).i_sb)?;
    let device = bpf_probe_read_kernel(&(*sb_ptr).s_dev)?;
    let inode_number = bpf_probe_read_kernel(&(*inode_ptr).i_ino)?;

    *dev = dev::encode(device);
    *ino = inode_number;
    *overlay = extract_overlay_layer(file);
    Ok(())
}

unsafe fn extract_overlay_layer(file: *const vmlinux::file) -> Overlay {
    let Ok(dentry_ptr) = bpf_probe_read_kernel(&(*file).f_path.dentry) else {
        return Overlay::None;
    };

    let Ok(sb_ptr) = bpf_probe_read_kernel(&(*dentry_ptr).d_sb) else {
        return Overlay::None;
    };

    let Ok(sb_magic) = bpf_probe_read_kernel(&(*sb_ptr).s_magic) else {
        return Overlay::None;
    };

    if sb_magic != OVERLAYFS_SUPER_MAGIC {
        return Overlay::None;
    }

    let Ok(vfs_inode_ptr) = bpf_probe_read_kernel(&(*dentry_ptr).d_inode) else {
        return Overlay::Lower;
    };

    // We need to compute the size of the inode struct at load time since it can change between
    // kernel versions
    // TODO(ekoops): actually we don't know if aya is able to patch the type size and patch is in
    //   some way; in other words, we don't know if this is the equivalent of doing
    //   bpf_core_type_size(struct inode).
    let inode_size = size_of::<vmlinux::inode>();
    let Ok(upper_dentry_ptr) = bpf_probe_read_kernel(
        vfs_inode_ptr
            .byte_add(inode_size)
            .cast::<*const vmlinux::dentry>(),
    ) else {
        return Overlay::Lower;
    };
    let Ok(upper_dentry_inode_ptr) = bpf_probe_read_kernel(&(*upper_dentry_ptr).d_inode) else {
        return Overlay::Lower;
    };
    match bpf_probe_read_kernel(&(*upper_dentry_inode_ptr).i_ino) {
        Ok(_) => Overlay::Upper,
        Err(_) => Overlay::Lower,
    }
}
