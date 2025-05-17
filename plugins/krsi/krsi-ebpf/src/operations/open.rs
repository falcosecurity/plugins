// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//! # Data extraction
//!
//! ## Kernel functions call graph (`openat` syscall path)
//! ```
//! SYSCALL_DEFINE4(openat, int, dfd, const char __user *, filename, int, flags, umode_t, mode)
//!     long do_sys_open(int dfd, const char __user *filename, int flags, umode_t mode);
//!         long do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
//!             struct file *do_filp_open(int dfd, struct filename *pathname,
//!                 const struct open_flags *op)
//!             void fd_install(unsigned int fd, struct file *file)
//! ```
//!
//! ## Kernel functions call graph (`openat2` syscall path)
//! ```
//! SYSCALL_DEFINE4(openat2, int, dfd, const char __user *, filename, struct open_how __user *, how,
//!     size_t, usize)
//!         long do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
//!             struct file *do_filp_open(int dfd, struct filename *pathname,
//!                 const struct open_flags *op)
//!             void fd_install(unsigned int fd, struct file *file)
//! ```
//!
//! ## Kernel functions call graph (`io_uring` IORING_OP_OPENAT path)
//! ```
//! int io_openat(struct io_kiocb *req, unsigned int issue_flags)
//!     int io_openat2(struct io_kiocb *req, unsigned int issue_flags)
//!         struct file *do_filp_open(int dfd, struct filename *pathname,
//!             const struct open_flags *op)
//!         if (...) void fd_install(unsigned int fd, struct file *file)
//!         else (...) int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
//!             struct file *file, unsigned int file_slot);
//! ```
//!
//! ## Kernel functions call graph (`io_uring` IORING_OP_OPENAT2 path)
//! ```
//! int io_openat2(struct io_kiocb *req, unsigned int issue_flags)
//!     struct file *do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
//!     if (...) void fd_install(unsigned int fd, struct file *file)
//!     else (...) int io_fixed_fd_install(struct io_kiocb *req, unsigned int issue_flags,
//!         struct file *file, unsigned int file_slot);
//! ```
//!
//! ## Extraction flow
//! 1. `fentry:do_sys_openat2`|`fentry:io_openat2`
//! 2. `fexit:security_file_open`
//! 3. `fexit:fd_install` | `fexit:io_fixed_fd_install`
//! 4. `fexit:do_sys_openat2` | `fexit:io_openat2`

use aya_ebpf::{
    cty::c_uint,
    macros::{fentry, fexit},
    programs::{FEntryContext, FExitContext},
    EbpfContext,
};
use krsi_common::{scap as scap_shared, EventType};
use krsi_ebpf_core::{wrap_arg, File};

use crate::{
    files,
    operations::{helpers, writer_helpers},
    scap, shared_state,
    shared_state::op_info::{OpInfo, OpenData},
    FileDescriptor,
};

#[fentry]
fn do_sys_openat2_e(ctx: FEntryContext) -> u32 {
    try_openat2_e(ctx).unwrap_or(1)
}

fn try_openat2_e(ctx: FEntryContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let op_info = OpInfo::Open(OpenData {
        fd_installed: false,
    });
    shared_state::op_info::insert(pid, &op_info)
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
    if unsafe { shared_state::op_info::get(pid) }.is_none() {
        return Ok(0);
    };

    let ret: i64 = unsafe { ctx.arg(1) };
    if ret != 0 {
        return shared_state::op_info::remove(pid);
    }

    let Some(auxbuf) = shared_state::auxiliary_buffer() else {
        return shared_state::op_info::remove(pid);
    };

    let mut writer = auxbuf.writer();
    writer_helpers::preload_event_header(&mut writer, EventType::Open);

    // Parameter 1: name.
    let file: File = wrap_arg(unsafe { ctx.arg(0) });
    let path = file.f_path();
    match writer_helpers::store_path_param(&mut writer, &path) {
        Ok(_) => Ok(0),
        Err(_) => shared_state::op_info::remove(pid),
    }
}

pub fn try_fd_install_x(
    ctx: &FExitContext,
    file_descriptor: FileDescriptor,
    file: &File,
) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(OpInfo::Open(op_data)) = (unsafe { shared_state::op_info::get_mut(pid) }) else {
        return Ok(0);
    };

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    // Don't call writer.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:security_file_open`.

    // Parameter 2: fd.
    // Parameter 3: file_index.
    writer_helpers::store_file_descriptor_param(&mut writer, file_descriptor)?;

    let (dev, ino, overlay) = files::dev_ino_overlay(file).unwrap_or((0, 0, files::Overlay::None));

    // Parameter 4: flags.
    let flags = file.f_flags().unwrap_or(0);
    let mut scap_flags = scap::encode_open_flags(flags);
    scap_flags |= match overlay.try_into() {
        Ok(files::Overlay::Upper) => scap_shared::PPM_FD_UPPER_LAYER,
        Ok(files::Overlay::Lower) => scap_shared::PPM_FD_LOWER_LAYER,
        _ => 0,
    };
    let mode: c_uint = file.f_mode().unwrap_or(0);
    scap_flags |= scap::encode_fmode_created(mode);

    writer.store_param(scap_flags)?;

    // Parameter 5: mode.
    writer.store_param(scap::encode_open_mode(flags, mode))?;

    // Parameter 6: dev.
    writer.store_param(dev as u32)?;

    // Parameter 7: ino.
    writer.store_param(ino)?;

    op_data.fd_installed = true;

    Ok(0)
}

#[fexit]
pub fn io_openat2_x(ctx: FExitContext) -> u32 {
    try_openat2_x(ctx).unwrap_or(1)
}

fn try_openat2_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(OpInfo::Open(OpenData { fd_installed })) =
        (unsafe { shared_state::op_info::get(pid) })
    else {
        return Ok(0);
    };
    let _ = shared_state::op_info::remove(pid);

    if !fd_installed {
        return Ok(0);
    }

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    // Don't call writer.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:fd_install` or `fexit:io_fixed_fd_install`.

    // Parameter 8: iou_ret.
    let iou_ret: i64 = unsafe { ctx.arg(2) };
    writer.store_param(iou_ret)?;

    writer.finalize_event_header();
    helpers::submit_event(auxbuf.as_bytes()?);
    Ok(0)
}

#[fexit]
pub fn do_sys_openat2_x(ctx: FExitContext) -> u32 {
    try_do_sys_openat2_x(ctx).unwrap_or(1)
}

fn try_do_sys_openat2_x(ctx: FExitContext) -> Result<u32, i64> {
    let pid = ctx.pid();
    let Some(&OpInfo::Open(OpenData { fd_installed })) =
        (unsafe { shared_state::op_info::get(pid) })
    else {
        return Ok(0);
    };
    let _ = shared_state::op_info::remove(pid);

    if !fd_installed {
        return Ok(0);
    }

    let auxbuf = shared_state::auxiliary_buffer().ok_or(1)?;
    let mut writer = auxbuf.writer();
    // Don't call writer.preload_event_header, because we want to continue to append to the work
    // already done on `fexit:fd_install`.

    // Parameter 8: iou_ret.
    writer.store_empty_param()?;

    writer.finalize_event_header();
    helpers::submit_event(auxbuf.as_bytes()?);
    Ok(0)
}
