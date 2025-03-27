#![no_std]
#![no_main]

use aya_ebpf::macros::fentry;
use aya_ebpf::programs::FEntryContext;

mod auxmap;
mod connect;
mod file;
mod sockets;
mod open;
mod shared_maps;
#[allow(clippy::all)]
#[allow(dead_code)]
#[allow(non_camel_case_types)]
#[allow(non_snake_case)]
#[allow(non_upper_case_globals)]
#[rustfmt::skip]
mod vmlinux;
mod scap;
mod defs;

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[fentry]
fn fd_install(ctx: FEntryContext) -> u32 {
    let a = [open::try_fd_install, connect::try_fd_install];
    let mut res = 0;
    for f in a {
        res |= f(&ctx).unwrap_or(1);
    }
    res
}
