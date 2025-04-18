#![no_std]

pub mod scap;

#[derive(Copy, Clone, Debug)]
#[repr(u16)]
pub enum EventType {
    None = 0,
    Open = 1,
    Connect = 2,
    Socket = 3,
    Symlinkat = 4,
    Linkat = 5,
    Unlinkat = 6,
    Mkdirat = 7,
    Renameat = 8,
    Bind = 9,
}

impl Default for EventType {
    fn default() -> Self {
        Self::None
    }
}

impl TryFrom<u16> for EventType {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            x if x == EventType::Open as u16 => Ok(EventType::Open),
            x if x == EventType::Connect as u16 => Ok(EventType::Connect),
            x if x == EventType::Socket as u16 => Ok(EventType::Socket),
            x if x == EventType::Symlinkat as u16 => Ok(EventType::Symlinkat),
            x if x == EventType::Linkat as u16 => Ok(EventType::Linkat),
            x if x == EventType::Unlinkat as u16 => Ok(EventType::Unlinkat),
            x if x == EventType::Mkdirat as u16 => Ok(EventType::Mkdirat),
            x if x == EventType::Renameat as u16 => Ok(EventType::Renameat),
            x if x == EventType::Bind as u16 => Ok(EventType::Bind),
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
