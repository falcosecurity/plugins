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

#![no_std]
#![no_main]

use aya_ebpf::{macros::fexit, programs::FExitContext};
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, File};
use operations::*;

mod auxbuf;
mod defs;
mod files;
mod iouring;
mod operations;
mod scap;
mod shared_state;
mod sockets;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[fexit]
fn fd_install_x(ctx: FExitContext) -> u32 {
    let file_descriptor = FileDescriptor::Fd(unsafe { ctx.arg(0) });
    let file: File = wrap_arg(unsafe { ctx.arg(1) });
    let handlers = [open::try_fd_install_x];
    let mut res = 0;
    for handler in handlers {
        res |= handler(&ctx, file_descriptor, &file).unwrap_or(1);
    }
    res
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum FileDescriptor {
    Fd(i32),
    FileIndex(i32),
}

#[fexit]
fn io_fixed_fd_install_x(ctx: FExitContext) -> u32 {
    let ret = unsafe { ctx.arg(4) };
    if ret < 0 {
        return 0;
    }

    let file_slot: u32 = unsafe { ctx.arg(3) };
    let file_index = if file_slot == defs::IORING_FILE_INDEX_ALLOC {
        ret
    } else {
        (file_slot - 1) as i32
    };
    let file_descriptor = FileDescriptor::FileIndex(file_index);
    let file: File = wrap_arg(unsafe { ctx.arg(2) });

    let handlers = [open::try_fd_install_x];
    let mut res = 0;
    for handler in handlers {
        res |= handler(&ctx, file_descriptor, &file).unwrap_or(1);
    }
    res
}

// TODO(ekoops): move this function elsewhere.
pub fn get_event_num_params(event_type: EventType) -> u8 {
    match event_type.try_into() {
        // TODO(ekoops): try to generate the following numbers automatically.
        Ok(EventType::Open) => 8,
        Ok(EventType::Connect) => 5,
        Ok(EventType::Socket) => 6,
        Ok(EventType::Symlinkat) => 5,
        Ok(EventType::Linkat) => 7,
        Ok(EventType::Unlinkat) => 5,
        Ok(EventType::Mkdirat) => 5,
        Ok(EventType::Renameat) => 7,
        Ok(EventType::Bind) => 5,
        _ => 0,
    }
}
