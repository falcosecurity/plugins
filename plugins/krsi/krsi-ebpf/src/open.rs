//! Flow for extracting parameters upon file opening procedures:
//! 1. `fentry:do_sys_openat2` - detect the start of an opening request and annotate it by putting
//! the pid of the current thread in the `OPEN_PIDS` map
//! 2. `fexit:security_file_open` - verify that the opening request has been accepted, extract the
//! file path, put the extracted file path in the auxmap final location and write the association
//! between the pid of the current thread and the file path length in the `OPEN_PIDS` map. If any of
//! aforementioned operation fails, ensure the pid is removed from the `OPEN_PIDS` map.
//! 3. `fentry:fd_install` - verify that an opening request is currently in progress by checking
//! the presence of an association for the current thread's pid in the `OPEN_PIDS` map, extract the
//! file path length from the aforementioned association, extract the other relevant parameters for
//! the opening request, complete the event in the auxiliary map by leveraging the information on
//! the length of the already-extracted file path and submit the event.
//! 1. `fexit:do_sys_openat2` - ensure the association for the current thread's pid is removed from
//! the `OPEN_PIDS` map

use crate::{file, scap, shared_maps, vmlinux};
use aya_ebpf::cty::{c_int, c_uint};
use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::macros::{fentry, fexit};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{FEntryContext, FExitContext, RetProbeContext};
use aya_ebpf::EbpfContext;
use aya_log_ebpf::info;
use core::ptr::null_mut;
use krsi_common::EventType;

mod maps;

#[fentry]
pub fn do_sys_openat2_e(ctx: FEntryContext) -> u32 {
    let pid = ctx.pid();
    const ZERO: u32 = 0;
    match maps::get_open_pids_map().insert(&pid, &ZERO, 0) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}

#[fexit]
pub fn security_file_open(ctx: FExitContext) -> u32 {
    unsafe { try_security_file_open(ctx) }.unwrap_or(1)
}

const MAX_PATH: u16 = 4096;

unsafe fn try_security_file_open(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let open_pids_map = maps::get_open_pids_map();
    let Some(file_path_len) = open_pids_map.get_ptr_mut(&pid) else {
        return Ok(0);
    };

    let ret: c_int = unsafe { ctx.arg(1) };
    if ret != 0 {
        return remove_open_pid(open_pids_map, pid);
    }

    let Some(auxmap) = shared_maps::get_auxiliary_map() else {
        return remove_open_pid(open_pids_map, pid);
    };

    auxmap.preload_event_header(EventType::FdInstall);
    auxmap.store_param(0_u64);
    let file: *const vmlinux::file = ctx.arg(0);
    let path_ptr = &(*file).f_path as *const vmlinux::path;
    let Ok(written_bytes) = auxmap.store_path_param(path_ptr, MAX_PATH) else {
        return remove_open_pid(open_pids_map, pid);
    };

    *file_path_len = written_bytes as u32;
    Ok(0)
}

fn remove_open_pid(open_pids_map: &HashMap<u32, u32>, pid: u32) -> Result<u32, i64> {
    match open_pids_map.remove(&pid) {
        Ok(_) => Ok(0),
        Err(_) => Err(1),
    }
}

#[fentry]
pub fn fd_install(ctx: FEntryContext) -> u32 {
    unsafe { try_fd_install(ctx) }.unwrap_or(1)
}

unsafe fn try_fd_install(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(&file_path_len) = maps::get_open_pids_map().get(&pid) else {
        return Ok(0);
    };
    let file_path_len = file_path_len as u16;

    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    auxmap.preload_event_header(EventType::FdInstall);

    // Parameter 1: fd.
    let fd: c_uint = ctx.arg(0);
    auxmap.store_param(fd as i64);

    let file = file::File::new(ctx.arg(1));
    let (dev, ino, overlay) = file
        .extract_dev_ino_overlay()
        .unwrap_or((0, 0, file::Overlay::None));

    // Parameter 2: name.
    // The file path has already been stored by the fexit program on `security_file_open` hook, as
    // it is only one of the few places allowed to call the `bpf_d_path` helper to obtain the full
    // file path.
    auxmap.skip_param(file_path_len);

    // Parameter 3: flags.
    let flags = file.extract_flags().unwrap_or(0);
    let mut scap_flags = scap::encode_open_flags(flags);
    scap_flags |= match overlay.try_into() {
        Ok(file::Overlay::Upper) => scap::PPM_FD_UPPER_LAYER,
        Ok(file::Overlay::Lower) => scap::PPM_FD_LOWER_LAYER,
        _ => 0,
    };
    let mode: c_uint = file.extract_mode().unwrap_or(0);
    scap_flags |= scap::encode_fmode_created(mode);

    auxmap.store_param(scap_flags);

    // Parameter 4: mode.
    auxmap.store_param(scap::encode_open_mode(flags, mode));

    // Parameter 5: dev.
    auxmap.store_param(dev as u32);

    // Parameter 6: ino.
    auxmap.store_param(ino);

    auxmap.finalize_event_header();
    auxmap.submit_event();

    #[cfg(debug_assertions)]
    {
        let name_ptr = file.extract_name().unwrap_or(null_mut());
        let mut buf: [u8; 128] = [0; 128];
        let name = unsafe {
            core::str::from_utf8_unchecked(bpf_probe_read_kernel_str_bytes(name_ptr, &mut buf)?)
        };
        let pid = ctx.pid();
        info!(
            &ctx,
            "[fd_install]: tid={}, fd={}, name={}, mode={}, flags={} dev={} ino={}",
            pid,
            fd,
            name,
            mode,
            flags,
            dev,
            ino
        );
    }

    Ok(0)
}

#[fexit]
pub fn do_sys_openat2_x(ctx: FExitContext) -> u32 {
    let pid = ctx.pid();
    match maps::get_open_pids_map().remove(&pid) {
        Ok(_) => 0,
        Err(_) => 1,
    }
}
