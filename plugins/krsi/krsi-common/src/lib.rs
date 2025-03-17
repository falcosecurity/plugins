#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RingBufEvent {
    pub pid: u32,
    pub tgid: u32,
}
