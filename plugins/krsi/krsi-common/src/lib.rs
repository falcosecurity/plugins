#![no_std]

pub mod scap;

#[derive(Copy, Clone, Debug)]
#[repr(u16)]
pub enum EventType {
    Open = 0,
    Connect = 1,
    Socket = 2,
}

impl TryFrom<u16> for EventType {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == EventType::Open as u16 => Ok(EventType::Open),
            x if x == EventType::Connect as u16 => Ok(EventType::Connect),
            x if x == EventType::Socket as u16 => Ok(EventType::Socket),
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
