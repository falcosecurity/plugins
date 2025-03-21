#![no_std]
#![no_main]

use aya_ebpf::cty::{c_int, c_uint};
use aya_ebpf::helpers::{bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes};
use aya_ebpf::macros::{fentry, fexit, kretprobe};
use aya_ebpf::programs::{FEntryContext, FExitContext, RetProbeContext};
use aya_ebpf::{macros::kprobe, programs::ProbeContext, EbpfContext};
use aya_log_ebpf::info;
use core::ptr::null_mut;
use krsi_common::EventType;

mod auxmap;
mod file;
mod maps;
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[rustfmt::skip]
mod vmlinux;
mod defs;
mod scap;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[fexit]
pub fn security_file_open(ctx: FExitContext) -> u32 {
    unsafe { try_security_file_open(ctx) }.unwrap_or(1)
}

unsafe fn try_security_file_open(ctx: FExitContext) -> Result<u32, i64> {
    let ret: c_int = unsafe { ctx.arg(1) };
    if ret != 0 {
        return Ok(0);
    }

    let auxmap = maps::get_auxiliary_map().ok_or(1_i64)?;
    auxmap.preload_event_header(EventType::FdInstall);
    auxmap.store_param(0_u64);
    let file: *const vmlinux::file = ctx.arg(0);
    let path_ptr = &(*file).f_path as *const vmlinux::path;
    let written_bytes = auxmap.store_path_param(path_ptr, MAX_PATH)? as u32;
    let pid = ctx.pid();
    maps::get_open_pids_map().insert(&pid, &written_bytes, 0)?;
    Ok(0)
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

    let _ = try_fd_install_extract_params(ctx, file_path_len);
    maps::get_open_pids_map().remove(&pid)?;

    Ok(0)
}

const MAX_PATH: u16 = 4096;

unsafe fn try_fd_install_extract_params(
    ctx: FEntryContext,
    file_path_len: u16,
) -> Result<u32, i64> {
    let auxmap = maps::get_auxiliary_map().ok_or(1_i64)?;
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
