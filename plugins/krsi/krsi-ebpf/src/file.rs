use crate::vmlinux;
use aya_ebpf::cty::{c_long, c_uint};
use aya_ebpf::helpers::bpf_probe_read_kernel;
use core::ffi::{c_uchar, c_void};

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

pub struct File {
    file: *const vmlinux::file,
}

impl File {
    pub fn new(file: *const vmlinux::file) -> Self {
        Self { file }
    }

    pub unsafe fn extract_dev_ino_overlay(&self) -> Result<(vmlinux::dev_t, u64, Overlay), i64> {
        let inode = bpf_probe_read_kernel(&(*self.file).f_inode)?;
        let sb = bpf_probe_read_kernel(&(*inode).i_sb)?;
        let dev = bpf_probe_read_kernel(&(*sb).s_dev)?;
        let ino = bpf_probe_read_kernel(&(*inode).i_ino)?;
        Ok((dev::encode(dev), ino, self.extract_overlay_layer()))
    }

    unsafe fn extract_overlay_layer(&self) -> Overlay {
        let Ok(dentry) = bpf_probe_read_kernel(&(*self.file).f_path.dentry) else {
            return Overlay::None;
        };

        let Ok(sb) = bpf_probe_read_kernel(&(*dentry).d_sb) else {
            return Overlay::None;
        };

        let Ok(sb_magic) = bpf_probe_read_kernel(&(*sb).s_magic) else {
            return Overlay::None;
        };

        if sb_magic != OVERLAYFS_SUPER_MAGIC {
            return Overlay::None;
        }

        let Ok(vfs_inode) = bpf_probe_read_kernel(&(*dentry).d_inode) else {
            return Overlay::Lower;
        };

        // We need to compute the size of the inode struct at load time since it can change between
        // kernel versions
        // TODO(ekoops): actually we don't know if aya is able to patch the type size and patch is
        //   in some way; in other words, we don't know if this is the equivalent of doing
        //   `bpf_core_type_size(struct inode)`.
        let inode_size = size_of::<vmlinux::inode>();
        let Ok(upper_dentry) = bpf_probe_read_kernel(
            vfs_inode
                .byte_add(inode_size)
                .cast::<*const vmlinux::dentry>(),
        ) else {
            return Overlay::Lower;
        };

        let Ok(upper_dentry_inode) = bpf_probe_read_kernel(&(*upper_dentry).d_inode) else {
            return Overlay::Lower;
        };

        match bpf_probe_read_kernel(&(*upper_dentry_inode).i_ino) {
            Ok(_) => Overlay::Upper,
            Err(_) => Overlay::Lower,
        }
    }

    pub unsafe fn extract_flags(&self) -> Result<c_uint, c_long> {
        bpf_probe_read_kernel(&(*self.file).f_flags)
    }

    pub unsafe fn extract_mode(&self) -> Result<vmlinux::fmode_t, c_long> {
        bpf_probe_read_kernel(&(*self.file).f_mode)
    }

    /// Extract file's private_data field and convert its value to a `* const T`.
    pub fn extract_private_data<T>(&self) -> Result<*const T, c_long> {
        unsafe { bpf_probe_read_kernel(&(*self.file).private_data.cast_const().cast::<T>()) }
    }

    #[cfg(debug_assertions)]
    pub unsafe fn extract_name(&self) -> Result<*const c_uchar, c_long> {
        let dentry = bpf_probe_read_kernel(&(*self.file).f_path.dentry)?;
        bpf_probe_read_kernel(&(*dentry).d_name.name)
    }
}
