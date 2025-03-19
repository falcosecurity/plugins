#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct RingBufEvent {
    pub pid: u32,
    pub tgid: u32,
    // Taken from PPME_SYSCALL_OPEN_X
    pub fd: u32,
    pub name: [u8; 128], // type TBD
    pub flags: u32,
    pub mode: u32,
    pub dev: u32,
    pub ino: u64,
}

#[derive(Copy, Clone, Debug)]
#[repr(u16)]
pub enum EventType {
    FdInstall = 50,
}

impl TryFrom<u16> for EventType {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == EventType::FdInstall as u16 => Ok(EventType::FdInstall),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct EventHeader {
    pub ts: u64,
    pub tid: u64,
    pub len: u32,
    pub evt_type: EventType,
    pub nparams: u32,
}
