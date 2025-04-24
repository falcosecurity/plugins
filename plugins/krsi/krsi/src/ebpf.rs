use aya::{
    maps::RingBuf,
    programs::{FEntry, FExit},
    EbpfLoader,
};
use aya_log::EbpfLogger;
use krsi_common::flags::{FeatureFlags, OpFlags};
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME, CLOCK_REALTIME};
use log::debug;

pub struct Ebpf {
    btf: aya::Btf,
    ebpf: aya::Ebpf,
    feature_flags: FeatureFlags,
    op_flags: OpFlags,
}

enum ProgKind {
    Fentry,
    Fexit,
}

struct ProgDef {
    kind: ProgKind,
    name: &'static str,
    fn_name: &'static str,
    feature_flags: FeatureFlags,
    op_flags: OpFlags,
}

impl ProgDef {
    const fn new(
        kind: ProgKind,
        name: &'static str,
        fn_name: &'static str,
        feature_flags: FeatureFlags,
        op_flags: OpFlags,
    ) -> Self {
        Self {
            kind,
            name,
            fn_name,
            feature_flags,
            op_flags,
        }
    }
}

// Programs are conditionally loaded and attached (conditionally, depending on their flags) by
// taking into account the definition order.
const PROG_DEFS: &'static [ProgDef] = &[
    // Open programs.
    ProgDef::new(
        ProgKind::Fexit,
        "fd_install_x",
        "fd_install",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::OPEN,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "io_fixed_fd_install_x",
        "io_fixed_fd_install",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::OPEN,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "security_file_open_x",
        "security_file_open",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::OPEN,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "io_openat2_x",
        "io_openat2",
        FeatureFlags::IO_URING,
        OpFlags::OPEN,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "io_openat2_e",
        "io_openat2",
        FeatureFlags::IO_URING,
        OpFlags::OPEN,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "do_sys_openat2_x",
        "do_sys_openat2",
        FeatureFlags::SYSCALLS,
        OpFlags::OPEN,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "do_sys_openat2_e",
        "do_sys_openat2",
        FeatureFlags::SYSCALLS,
        OpFlags::OPEN,
    ),
    // Socket programs.
    ProgDef::new(
        ProgKind::Fexit,
        "io_socket_x",
        "io_socket",
        FeatureFlags::IO_URING,
        OpFlags::SOCKET,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "__sys_socket_x",
        "__sys_socket",
        FeatureFlags::SYSCALLS,
        OpFlags::SOCKET,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "__sys_connect_file_x",
        "__sys_connect_file",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::CONNECT,
    ),
    // Connect programs.
    ProgDef::new(
        ProgKind::Fexit,
        "io_connect_x",
        "io_connect",
        FeatureFlags::IO_URING,
        OpFlags::CONNECT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "io_connect_e",
        "io_connect",
        FeatureFlags::IO_URING,
        OpFlags::CONNECT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "__sys_connect_x",
        "__sys_connect",
        FeatureFlags::SYSCALLS,
        OpFlags::CONNECT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "__sys_connect_e",
        "__sys_connect",
        FeatureFlags::SYSCALLS,
        OpFlags::CONNECT,
    ),
    // Symlinkat programs.
    ProgDef::new(
        ProgKind::Fexit,
        "do_symlinkat_x",
        "do_symlinkat",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::SYMLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "io_symlinkat_x",
        "io_symlinkat",
        FeatureFlags::IO_URING,
        OpFlags::SYMLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "io_symlinkat_e",
        "io_symlinkat",
        FeatureFlags::IO_URING,
        OpFlags::SYMLINKAT,
    ),
    // Linkat programs.
    ProgDef::new(
        ProgKind::Fexit,
        "do_linkat_x",
        "do_linkat",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::LINKAT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "io_linkat_x",
        "io_linkat",
        FeatureFlags::IO_URING,
        OpFlags::LINKAT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "io_linkat_e",
        "io_linkat",
        FeatureFlags::IO_URING,
        OpFlags::LINKAT,
    ),
    // Unlinkat programs.
    ProgDef::new(
        ProgKind::Fexit,
        "io_unlinkat_x",
        "io_unlinkat",
        FeatureFlags::IO_URING,
        OpFlags::UNLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "__x64_sys_unlink_x",
        "__x64_sys_unlink",
        FeatureFlags::SYSCALLS,
        OpFlags::UNLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "__x64_sys_unlinkat_x",
        "__x64_sys_unlinkat",
        FeatureFlags::SYSCALLS,
        OpFlags::UNLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "do_unlinkat_x",
        "do_unlinkat",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::UNLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "do_rmdir_x",
        "do_rmdir",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::UNLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "io_unlinkat_e",
        "io_unlinkat",
        FeatureFlags::IO_URING,
        OpFlags::UNLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "__x64_sys_unlink_e",
        "__x64_sys_unlink",
        FeatureFlags::SYSCALLS,
        OpFlags::UNLINKAT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "__x64_sys_unlinkat_e",
        "__x64_sys_unlinkat",
        FeatureFlags::SYSCALLS,
        OpFlags::UNLINKAT,
    ),
    // Mkdirat programs.
    ProgDef::new(
        ProgKind::Fexit,
        "do_mkdirat_x",
        "do_mkdirat",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::MKDIRAT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "io_mkdirat_x",
        "io_mkdirat",
        FeatureFlags::IO_URING,
        OpFlags::MKDIRAT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "io_mkdirat_e",
        "io_mkdirat",
        FeatureFlags::IO_URING,
        OpFlags::MKDIRAT,
    ),
    // Renameat programs.
    ProgDef::new(
        ProgKind::Fexit,
        "do_renameat2_x",
        "do_renameat2",
        FeatureFlags::from_bits_truncate(
            FeatureFlags::IO_URING.bits() | FeatureFlags::SYSCALLS.bits(),
        ),
        OpFlags::RENAMEAT,
    ),
    ProgDef::new(
        ProgKind::Fexit,
        "io_renameat_x",
        "io_renameat",
        FeatureFlags::IO_URING,
        OpFlags::RENAMEAT,
    ),
    ProgDef::new(
        ProgKind::Fentry,
        "io_renameat_e",
        "io_renameat",
        FeatureFlags::IO_URING,
        OpFlags::RENAMEAT,
    ),
    // Bind programs.
    // ProgDef::new(
    //     ProgKind::Fexit,
    //     "io_bind_x",
    //     "io_bind",
    //     FeatureFlags::IO_URING,
    //     OpFlags::BIND,
    // ),
    // ProgDef::new(
    //     ProgKind::Fentry,
    //     "io_bind_e",
    //     "io_bind",
    //     FeatureFlags::IO_URING,
    //     OpFlags::BIND,
    // ),
    ProgDef::new(
        ProgKind::Fexit,
        "__sys_bind_x",
        "__sys_bind",
        FeatureFlags::SYSCALLS,
        OpFlags::BIND,
    ),
];

impl Ebpf {
    pub fn try_new(
        enable_logging: bool,
        feature_flags: FeatureFlags,
        op_flags: OpFlags,
    ) -> Result<Self, anyhow::Error> {
        // Bump the memlock rlimit. This is needed for older kernels that don't use the
        // new memcg based accounting, see https://lwn.net/Articles/837122/
        let rlim = libc::rlimit {
            rlim_cur: libc::RLIM_INFINITY,
            rlim_max: libc::RLIM_INFINITY,
        };

        let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
        if ret != 0 {
            debug!("remove limit on locked memory failed, ret is: {}", ret);
        }

        let btf = aya::Btf::from_sys_fs()?;
        let cpus = num_cpus::get();
        let boot_time = Self::get_precise_boot_time()?;
        let feature_flags_bits = feature_flags.bits();
        let op_flags_bits = op_flags.bits();
        let mut ebpf = EbpfLoader::new()
            .set_max_entries("AUXILIARY_MAPS", cpus as u32)
            .set_global("BOOT_TIME", &boot_time, true)
            .set_global("FEATURE_FLAGS", &feature_flags_bits, true)
            .set_global("OP_FLAGS", &op_flags_bits, true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/krsi"
            )))?;

        if enable_logging {
            EbpfLogger::init(&mut ebpf)?;
        }

        Ok(Self {
            btf,
            ebpf,
            feature_flags,
            op_flags,
        })
    }

    fn get_precise_boot_time() -> Result<u64, anyhow::Error> {
        let mut boot_ts = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { clock_gettime(CLOCK_BOOTTIME, &mut boot_ts) } < 0 {
            return Err(anyhow::anyhow!("failed to get CLOCK_BOOTLINE"));
        }

        let mut wall_ts = timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        if unsafe { clock_gettime(CLOCK_REALTIME, &mut wall_ts) } < 0 {
            return Err(anyhow::anyhow!("failed to get CLOCK_REALTIME"));
        }

        Ok(Self::timespec_to_nsec(&wall_ts) - Self::timespec_to_nsec(&boot_ts))
    }

    fn timespec_to_nsec(ts: &timespec) -> u64 {
        (ts.tv_sec * 1000000000 + ts.tv_nsec) as u64
    }

    pub fn load_and_attach_programs(&mut self) -> Result<(), anyhow::Error> {
        let ebpf = &mut self.ebpf;
        let btf = &self.btf;

        for prog_def in PROG_DEFS {
            if prog_def.feature_flags.intersects(self.feature_flags)
                && prog_def.op_flags.intersects(self.op_flags)
            {
                Self::load_and_attach_program(ebpf, btf, prog_def)?
            }
        }

        Ok(())
    }

    fn load_and_attach_program(
        ebpf: &mut aya::Ebpf,
        btf: &aya::Btf,
        prog_def: &ProgDef,
    ) -> Result<(), anyhow::Error> {
        match prog_def.kind {
            ProgKind::Fentry => {
                let prog: &mut FEntry = ebpf.program_mut(prog_def.name).unwrap().try_into()?;
                prog.load(prog_def.fn_name, btf)?;
                prog.attach()?;
            }
            ProgKind::Fexit => {
                let prog: &mut FExit = ebpf.program_mut(prog_def.name).unwrap().try_into()?;
                prog.load(prog_def.fn_name, btf)?;
                prog.attach()?;
            }
        }
        Ok(())
    }

    pub fn ring_buffer(&mut self) -> Result<RingBuf<aya::maps::MapData>, anyhow::Error> {
        let ring_buf = RingBuf::try_from(self.ebpf.take_map("EVENTS").unwrap())?;
        Ok(ring_buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[ignore]
    fn load_and_attach_programs() {
        let feature_flags = FeatureFlags::all();
        let op_flags = OpFlags::all();
        let mut ebpf = Ebpf::try_new(false, feature_flags, op_flags).unwrap();
        ebpf.load_and_attach_programs().unwrap()
    }
}
