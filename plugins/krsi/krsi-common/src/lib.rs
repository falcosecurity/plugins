#![no_std]

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
    pub tgid_pid: u64,
    pub len: u32,
    pub evt_type: EventType,
    pub nparams: u32,
}
