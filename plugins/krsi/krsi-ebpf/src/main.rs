#![no_std]
#![no_main]

use aya_ebpf::{macros::kprobe, programs::ProbeContext};
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::maps::RingBuf;
use aya_ebpf::macros::map;
use krsi_common::RingBufEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(128 * 4096, 0); // 128 pages = 256KB

#[kprobe]
pub fn krsi(ctx: ProbeContext) -> u32 {
    match try_krsi(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_krsi(_ctx: ProbeContext) -> Result<u32, u32> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    let pid = (pid_tgid & 0xffffffff) as u32;
    if let Some(mut event_reserved) = EVENTS.reserve::<RingBufEvent>(0) {
        unsafe {
            (*event_reserved.as_mut_ptr()).pid = pid;
            (*event_reserved.as_mut_ptr()).tgid = tgid;
        }
        event_reserved.submit(0);
        Ok(0)
    } else {
        // should I return error here?
        Ok(0)
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
