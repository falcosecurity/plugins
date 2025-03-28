#![no_std]
#![no_main]

use aya_ebpf::macros::fexit;
use aya_ebpf::programs::FExitContext;

mod auxmap;
mod connect;
mod file;
mod open;
mod shared_maps;
mod sockets;
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
fn fd_install(ctx: FExitContext) -> u32 {
    let handlers = [open::try_fd_install, connect::try_fd_install];
    let mut res = 0;
    for handler in handlers {
        res |= handler(&ctx).unwrap_or(1);
    }
    res
}

#[repr(C)]
#[derive(Copy, Clone)]
pub enum FileDescriptor {
    Fd(i32),
    FileIndex(u32),
}

#[fexit]
fn io_fixed_fd_install(ctx: FExitContext) -> u32 {
    let handlers = [open::try_io_fixed_fd_install];
    let mut res = 0;
    for handler in handlers {
        res |= handler(&ctx).unwrap_or(1);
    }
    res
}
