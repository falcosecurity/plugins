#![no_std]
#![no_main]

use aya_ebpf::macros::fexit;
use aya_ebpf::programs::FExitContext;
use krsi_common::EventType;
use operations::*;

mod auxmap;
mod file;
mod shared_maps;
mod sockets;
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[rustfmt::skip]
/*
To regenerate `vmlinux.rs`:
aya-tool generate task_struct file inet_sock unix_sock sockaddr_in sockaddr_in6 io_uring_op \
    io_socket io_connect io_async_msghdr > krsi-ebpf/src/vmlinux.rs
*/
mod vmlinux;
mod defs;
mod helpers;
mod iouring;
mod operations;
mod scap;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[fexit]
fn fd_install_x(ctx: FExitContext) -> u32 {
    let file_descriptor = FileDescriptor::Fd(unsafe { ctx.arg(0) });
    let file = file::File::new(unsafe { ctx.arg(1) });
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
    let file = file::File::new(unsafe { ctx.arg(2) });

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
        Ok(EventType::Open) => 7,
        Ok(EventType::Connect) => 5,
        Ok(EventType::Socket) => 6,
        Ok(EventType::Symlinkat) => 5,
        _ => 0,
    }
}