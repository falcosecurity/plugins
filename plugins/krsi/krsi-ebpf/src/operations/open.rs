//! Flow for extracting parameters upon file opening procedures:
//! 1. `fentry:do_sys_openat2`|`fentry:io_openat2` - detect the start of an opening request and
//! annotate it by putting the pid of the current thread in the `OPEN_PIDS` map
//! 2. `fexit:security_file_open` - verify that the opening request has been accepted, extract the
//! file path, put the extracted file path in the auxmap final location and write the association
//! between the pid of the current thread and the file path length in the `OPEN_PIDS` map. If any of
//! aforementioned operations fail, ensure the pid is removed from the `OPEN_PIDS` map.
//! 3. `fexit:fd_install` | `fexit:io_fixed_fd_install` - verify that an opening request is
//! currently in progress by checking the presence of an association for the current thread's pid in
//! the `OPEN_PIDS` map, extract the file path length from the aforementioned association, extract
//! the other relevant parameters for the opening request, complete the event in the auxiliary map
//! by leveraging the information on the length of the already-extracted file path and submit the
//! event.
//! 4. `fexit:do_sys_openat2` | `fexit:io_openat2` - ensure the association for the current
//! thread's pid is removed from the `OPEN_PIDS` map

use crate::{defs, file, helpers, scap, shared_maps, vmlinux, FileDescriptor};
use aya_ebpf::cty::{c_int, c_uint};
use aya_ebpf::helpers::bpf_probe_read_kernel_str_bytes;
use aya_ebpf::macros::{fentry, fexit};
use aya_ebpf::maps::HashMap;
use aya_ebpf::programs::{FEntryContext, FExitContext};
use aya_ebpf::EbpfContext;
use aya_log_ebpf::info;
use core::ptr::null_mut;
use krsi_common::{scap as scap_shared, EventType};

mod maps;

#[fentry]
fn do_sys_openat2_e(ctx: FEntryContext) -> u32 {
    try_openat2_e(ctx).unwrap_or(1)
}

fn try_openat2_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    const ZERO: u32 = 0;
    helpers::try_insert_map_entry(maps::get_pids_map(), &pid, &ZERO)
}

#[fentry]
pub fn io_openat2_e(ctx: FEntryContext) -> u32 {
    try_openat2_e(ctx).unwrap_or(1)
}

#[fexit]
pub fn security_file_open_x(ctx: FExitContext) -> u32 {
    try_security_file_open_x(ctx).unwrap_or(1)
}

fn try_security_file_open_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let pids_map = maps::get_pids_map();
    if unsafe { pids_map.get(&pid) }.is_none() {
        return Ok(0);
    };

    let ret: c_int = unsafe { ctx.arg(1) };
    if ret != 0 {
        return helpers::try_remove_map_entry(pids_map, &pid);
    }

    let Some(auxmap) = shared_maps::get_auxiliary_map() else {
        return helpers::try_remove_map_entry(pids_map, &pid);
    };

    auxmap.preload_event_header(EventType::Open);

    // Parameter 1: name.
    let file: *const vmlinux::file = unsafe { ctx.arg(0) };
    let path = unsafe { &(*file).f_path } as *const vmlinux::path;
    match unsafe { auxmap.store_path_param(path, defs::MAX_PATH) } {
        Ok(_) => Ok(0),
        Err(_) => helpers::try_remove_map_entry(pids_map, &pid),
    }
}

pub fn try_fd_install_x(
    ctx: &FExitContext,
    file_descriptor: FileDescriptor,
    file: &file::File,
) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(&file_path_len) = (unsafe { maps::get_pids_map().get(&pid) }) else {
        return Ok(0);
    };
    let file_path_len = file_path_len as u16;

    let auxmap = shared_maps::get_auxiliary_map().ok_or(1)?;
    // Don't call auxmap.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:security_file_open`.

    // Parameter 2: fd.
    // Parameter 3: file_index.
    auxmap.store_file_descriptor_param(file_descriptor);

    let (dev, ino, overlay) = unsafe {
        file.extract_dev_ino_overlay()
            .unwrap_or((0, 0, file::Overlay::None))
    };

    // Parameter 4: flags.
    let flags = unsafe { file.extract_flags() }.unwrap_or(0);
    let mut scap_flags = scap::encode_open_flags(flags);
    scap_flags |= match overlay.try_into() {
        Ok(file::Overlay::Upper) => scap_shared::PPM_FD_UPPER_LAYER,
        Ok(file::Overlay::Lower) => scap_shared::PPM_FD_LOWER_LAYER,
        _ => 0,
    };
    let mode: c_uint = unsafe { file.extract_mode() }.unwrap_or(0);
    scap_flags |= scap::encode_fmode_created(mode);

    auxmap.store_param(scap_flags);

    // Parameter 5: mode.
    auxmap.store_param(scap::encode_open_mode(flags, mode));

    // Parameter 6: dev.
    auxmap.store_param(dev as u32);

    // Parameter 7: ino.
    auxmap.store_param(ino);

    auxmap.finalize_event_header();
    auxmap.submit_event();

    #[cfg(debug_assertions)]
    {
        let name = unsafe { file.extract_name() }.unwrap_or(null_mut());
        let mut buf: [u8; 128] = [0; 128];
        let name = unsafe {
            core::str::from_utf8_unchecked(bpf_probe_read_kernel_str_bytes(name, &mut buf)?)
        };
        let fd = match file_descriptor.try_into() {
            Ok(FileDescriptor::Fd(fd)) => fd,
            Ok(FileDescriptor::FileIndex(file_index)) => file_index,
        };
        let pid = ctx.pid();
        info!(
            ctx,
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
    try_openat2_x(ctx).unwrap_or(1)
}

fn try_openat2_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    helpers::try_remove_map_entry(maps::get_pids_map(), &pid)
}

#[fexit]
pub fn io_openat2_x(ctx: FExitContext) -> u32 {
    try_openat2_x(ctx).unwrap_or(1)
}
