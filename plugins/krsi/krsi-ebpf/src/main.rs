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
    let file_descriptor = FileDescriptor::Fd(unsafe { ctx.arg(0) });
    let file = file::File::new(unsafe { ctx.arg(1) });
    let handlers = [open::try_fd_install, connect::try_fd_install];
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
    FileIndex(u32),
}

#[fexit]
fn io_fixed_fd_install(ctx: FExitContext) -> u32 {
    let handlers = [open::try_fd_install, connect::try_fd_install];
    let ret = unsafe { ctx.arg(4) };
    if ret < 0 {
        return 0;
    }

    let file_slot: u32 = unsafe { ctx.arg(3) };
    let file_index = if file_slot == defs::IORING_FILE_INDEX_ALLOC {
        ret
    } else {
        file_slot - 1
    };
    let file_descriptor = FileDescriptor::FileIndex(file_index);
    let file = file::File::new(unsafe { ctx.arg(2) });

    let mut res = 0;
    for handler in handlers {
        res |= handler(&ctx, file_descriptor, &file).unwrap_or(1);
    }
    res
}
