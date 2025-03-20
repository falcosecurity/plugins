#![no_std]
#![no_main]

use aya_ebpf::cty::{c_int, c_uint};
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
};
use aya_ebpf::macros::kretprobe;
use aya_ebpf::programs::RetProbeContext;
use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_log_ebpf::info;
use krsi_common::EventType;
use crate::file::Overlay;

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

#[kretprobe]
pub fn security_file_open(ctx: RetProbeContext) -> u32 {
    try_security_file_open(ctx).unwrap_or(1)
}

fn try_security_file_open(ctx: RetProbeContext) -> Result<u32, i64> {
    let ret = ctx.ret::<c_int>().ok_or(1_i64)?;
    if ret != 0 {
        return Ok(0);
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xffffffff) as u32;
    maps::get_open_pids_map().insert(&pid, &pid, 0)?;
    Ok(0)
}

#[kprobe]
pub fn fd_install(ctx: ProbeContext) -> u32 {
    unsafe { try_fd_install(ctx) }.unwrap_or(1)
}

unsafe fn try_fd_install(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xffffffff) as u32;
    if maps::get_open_pids_map().get(&pid).is_none() {
        return Ok(0);
    }

    let _ = try_fd_install_extract_params(ctx);
    maps::get_open_pids_map().remove(&pid)?;

    Ok(0)
}

const MAX_PATH: u16 = 4096;

unsafe fn try_fd_install_extract_params(ctx: ProbeContext) -> Result<u32, i64> {
    let auxmap = maps::get_auxiliary_map().ok_or(1_i64)?;
    auxmap.preload_event_header(EventType::FdInstall);

    // Parameter 1: fd.
    let fd: c_uint = ctx.arg(0).ok_or(1_i64)?;
    auxmap.store_param(fd as i64);

    let file: *const vmlinux::file = ctx.arg(1).ok_or(1_i64)?;
    let mut dev = 0;
    let mut ino = 0;
    let mut overlay = file::Overlay::None;
    file::extract_dev_ino_overlay(file, &mut dev, &mut ino, &mut overlay)?;

    // Parameter 2: name.
    let dentry_ptr = bpf_probe_read_kernel(&(*file).f_path.dentry)?;
    let name_ptr = bpf_probe_read_kernel(&(*dentry_ptr).d_name.name)?;
    let mut buf: [u8; 128] = [0; 128];
    let name = unsafe {
        core::str::from_utf8_unchecked(bpf_probe_read_kernel_str_bytes(name_ptr, &mut buf)?)
    };
    auxmap.store_charbuf_param(name_ptr, MAX_PATH)?;

    // Parameter 3: flags.
    let flags = bpf_probe_read_kernel(&(*file).f_flags)?;
    let mut scap_flags = scap::encode_open_flags(flags);
    scap_flags |= match overlay.try_into() {
        Ok(Overlay::Upper) => scap::PPM_FD_UPPER_LAYER,
        Ok(Overlay::Lower) => scap::PPM_FD_LOWER_LAYER,
        _ => 0
    };
    let mode: c_uint = bpf_probe_read_kernel(&(*file).f_mode)?;
    scap_flags |= scap::encode_fmode_created(mode);

    auxmap.store_param(scap_flags);

    // Parameter 4: mode.
    auxmap.store_param(scap::encode_open_mode(flags, mode));

    // Parameter 5: dev.
    auxmap.store_param(dev as u32);

    // Parameter 6: ino.
    auxmap.store_param(ino);

    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid & 0xffffffff) as u32;
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

    auxmap.finalize_event_header();
    auxmap.submit_event();
    Ok(0)
}
