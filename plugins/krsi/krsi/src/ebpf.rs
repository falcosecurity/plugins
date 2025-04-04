use crate::flags::FeatureFlags;
use aya::maps::RingBuf;
use aya::programs::{FEntry, FExit};
use aya::EbpfLoader;
use aya_log::EbpfLogger;
use libc::{clock_gettime, timespec, CLOCK_BOOTTIME, CLOCK_REALTIME};
use log::debug;

pub struct Ebpf {
    btf: aya::Btf,
    ebpf: aya::Ebpf,
}

impl Ebpf {
    pub fn try_new(enable_logging: bool) -> Result<Self, anyhow::Error> {
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
        let mut ebpf = EbpfLoader::new()
            .set_max_entries("AUXILIARY_MAPS", cpus as u32)
            .set_global("BOOT_TIME", &boot_time, true)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/krsi"
            )))?;

        if enable_logging {
            EbpfLogger::init(&mut ebpf)?;
        }

        Ok(Self { btf, ebpf })
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

    pub fn load_and_attach_programs(
        &mut self,
        feature_flags: &FeatureFlags,
    ) -> Result<(), anyhow::Error> {
        let ebpf = &mut self.ebpf;
        let btf = &self.btf;

        Self::load_and_attach_open_programs(ebpf, btf, feature_flags)?;
        Self::load_and_attach_socket_programs(ebpf, btf, feature_flags)?;
        Self::load_and_attach_connect_programs(ebpf, btf, feature_flags)?;
        Self::load_and_attach_symlinkat_programs(ebpf, btf, feature_flags)?;
        Ok(())
    }

    fn load_and_attach_open_programs(
        ebpf: &mut aya::Ebpf,
        btf: &aya::Btf,
        feature_flags: &FeatureFlags,
    ) -> Result<(), anyhow::Error> {
        if !feature_flags.is_empty() {
            let fd_install_x_prog: &mut FExit =
                ebpf.program_mut("fd_install_x").unwrap().try_into()?;
            fd_install_x_prog.load("fd_install", btf)?;
            fd_install_x_prog.attach()?;

            let io_fixed_fd_install_x_prog: &mut FExit = ebpf
                .program_mut("io_fixed_fd_install_x")
                .unwrap()
                .try_into()?;
            io_fixed_fd_install_x_prog.load("io_fixed_fd_install", btf)?;
            io_fixed_fd_install_x_prog.attach()?;

            let sec_file_open_x_prog: &mut FExit = ebpf
                .program_mut("security_file_open_x")
                .unwrap()
                .try_into()?;
            sec_file_open_x_prog.load("security_file_open", btf)?;
            sec_file_open_x_prog.attach()?;
        }

        if feature_flags.contains(FeatureFlags::ENABLE_IO_URING_SUPPORT) {
            let io_openat2_x_prog: &mut FExit =
                ebpf.program_mut("io_openat2_x").unwrap().try_into()?;
            io_openat2_x_prog.load("io_openat2", btf)?;
            io_openat2_x_prog.attach()?;

            let io_openat2_e_prog: &mut FEntry =
                ebpf.program_mut("io_openat2_e").unwrap().try_into()?;
            io_openat2_e_prog.load("io_openat2", btf)?;
            io_openat2_e_prog.attach()?;
        }

        if feature_flags.contains(FeatureFlags::ENABLE_SYSCALLS_SUPPORT) {
            let do_sys_openat2_x_prog: &mut FExit =
                ebpf.program_mut("do_sys_openat2_x").unwrap().try_into()?;
            do_sys_openat2_x_prog.load("do_sys_openat2", btf)?;
            do_sys_openat2_x_prog.attach()?;

            let do_sys_openat2_e_prog: &mut FEntry =
                ebpf.program_mut("do_sys_openat2_e").unwrap().try_into()?;
            do_sys_openat2_e_prog.load("do_sys_openat2", btf)?;
            do_sys_openat2_e_prog.attach()?;
        }

        Ok(())
    }

    fn load_and_attach_socket_programs(
        ebpf: &mut aya::Ebpf,
        btf: &aya::Btf,
        feature_flags: &FeatureFlags,
    ) -> Result<(), anyhow::Error> {
        if feature_flags.contains(FeatureFlags::ENABLE_IO_URING_SUPPORT) {
            let io_socket_x_prog: &mut FExit =
                ebpf.program_mut("io_socket_x").unwrap().try_into()?;
            io_socket_x_prog.load("io_socket", btf)?;
            io_socket_x_prog.attach()?;
        }

        if feature_flags.contains(FeatureFlags::ENABLE_SYSCALLS_SUPPORT) {
            let sys_socket_x_prog: &mut FExit =
                ebpf.program_mut("__sys_socket_x").unwrap().try_into()?;
            sys_socket_x_prog.load("__sys_socket", btf)?;
            sys_socket_x_prog.attach()?;
        }

        Ok(())
    }

    fn load_and_attach_connect_programs(
        ebpf: &mut aya::Ebpf,
        btf: &aya::Btf,
        feature_flags: &FeatureFlags,
    ) -> Result<(), anyhow::Error> {
        if !feature_flags.is_empty() {
            let sys_connect_file_x_prog: &mut FExit = ebpf
                .program_mut("__sys_connect_file_x")
                .unwrap()
                .try_into()?;
            sys_connect_file_x_prog.load("__sys_connect_file", btf)?;
            sys_connect_file_x_prog.attach()?;
        }

        if feature_flags.contains(FeatureFlags::ENABLE_IO_URING_SUPPORT) {
            let io_connect_x_prog: &mut FExit =
                ebpf.program_mut("io_connect_x").unwrap().try_into()?;
            io_connect_x_prog.load("io_connect", btf)?;
            io_connect_x_prog.attach()?;

            let io_connect_e_prog: &mut FEntry =
                ebpf.program_mut("io_connect_e").unwrap().try_into()?;
            io_connect_e_prog.load("io_connect", btf)?;
            io_connect_e_prog.attach()?;
        }

        if feature_flags.contains(FeatureFlags::ENABLE_SYSCALLS_SUPPORT) {
            let sys_connect_x_prog: &mut FExit =
                ebpf.program_mut("__sys_connect_x").unwrap().try_into()?;
            sys_connect_x_prog.load("__sys_connect", btf)?;
            sys_connect_x_prog.attach()?;

            let sys_connect_e_prog: &mut FEntry =
                ebpf.program_mut("__sys_connect_e").unwrap().try_into()?;
            sys_connect_e_prog.load("__sys_connect", btf)?;
            sys_connect_e_prog.attach()?;
        }

        Ok(())
    }

    fn load_and_attach_symlinkat_programs(
        ebpf: &mut aya::Ebpf,
        btf: &aya::Btf,
        feature_flags: &FeatureFlags,
    ) -> Result<(), anyhow::Error> {
        if !feature_flags.is_empty() {
            let do_symlinkat_x_prog: &mut FExit =
                ebpf.program_mut("do_symlinkat_x").unwrap().try_into()?;
            do_symlinkat_x_prog.load("do_symlinkat", btf)?;
            do_symlinkat_x_prog.attach()?;
        }

        if feature_flags.contains(FeatureFlags::ENABLE_IO_URING_SUPPORT) {
            let io_symlinkat_x_prog: &mut FExit =
                ebpf.program_mut("io_symlinkat_x").unwrap().try_into()?;
            io_symlinkat_x_prog.load("io_symlinkat", btf)?;
            io_symlinkat_x_prog.attach()?;

            let io_symlinkat_e_prog: &mut FEntry =
                ebpf.program_mut("io_symlinkat_e").unwrap().try_into()?;
            io_symlinkat_e_prog.load("io_symlinkat", btf)?;
            io_symlinkat_e_prog.attach()?;
        }

        Ok(())
    }

    pub fn ring_buffer(&mut self) -> Result<RingBuf<aya::maps::MapData>, anyhow::Error> {
        let ring_buf = RingBuf::try_from(self.ebpf.take_map("EVENTS").unwrap())?;
        Ok(ring_buf)
    }
}
