#![no_std]
#![no_main]

use aya_ebpf::{macros::fexit, programs::FExitContext};
use krsi_common::EventType;
use krsi_ebpf_core::{wrap_arg, File};
use operations::*;

mod auxmap;
mod defs;
mod files;
mod helpers;
mod iouring;
mod operations;
mod scap;
mod shared_maps;
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
