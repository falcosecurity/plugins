use std::ffi::{CStr, CString};
use byteorder::ReadBytesExt;
use byteorder::NativeEndian;
use krsi_common::EventHeader;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KrsiEvent {
    pub pid: u32,
    pub tid: u32,
    pub content: KrsiEventContent,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum KrsiEventContent {
    Open {
        fd: i32,
        file_index: i32,
        name: CString,
        flags: u32,
        mode: u32,
        dev: u32,
        ino: u64,
    },
}

#[derive(thiserror::Error)]
#[derive(Debug)]
pub enum RingbufParseError {
    #[error("Truncated event")]
    TruncatedEvent,
    #[error("Missing NUL terminator")]
    MissingNulTerminator,
    #[error("Invalid event type {0}")]
    InvalidType(u16),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Not yet implemented")]
    NotYetImplemented,
}

fn read_event_header(buf: &mut &[u8]) -> Result<EventHeader, RingbufParseError> {
    let ts = buf.read_u64::<NativeEndian>()?;
    let tgid_pid = buf.read_u64::<NativeEndian>()?;
    let len = buf.read_u32::<NativeEndian>()?;
    let evt_type = buf.read_u16::<NativeEndian>()?;
    let evt_type: krsi_common::EventType = evt_type.try_into().map_err(|_| RingbufParseError::InvalidType(evt_type))?;
    let nparams = buf.read_u32::<NativeEndian>()?;

    Ok(EventHeader {
        ts,
        tgid_pid,
        len,
        evt_type,
        nparams,
    })
}

trait FromBytes<'a>: Sized {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, RingbufParseError>;
}

impl FromBytes<'_> for u64 {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, RingbufParseError> {
        Ok(buf.read_u64::<NativeEndian>()?)
    }
}

impl FromBytes<'_> for u32 {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, RingbufParseError> {
        Ok(buf.read_u32::<NativeEndian>()?)
    }
}

impl FromBytes<'_> for i32 {
    fn from_bytes(buf: &mut &[u8]) -> Result<Self, RingbufParseError> {
        Ok(buf.read_i32::<NativeEndian>()?)
    }
}

impl<'a> FromBytes<'a> for &'a CStr {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, RingbufParseError> {
        CStr::from_bytes_until_nul(buf).map_err(|_| RingbufParseError::MissingNulTerminator)
    }
}

fn next_field<'a, T>(lengths: &mut &[u8], payload: &mut &'a [u8], fallback: Result<T, RingbufParseError>) -> Result<T, RingbufParseError>
where
    T: FromBytes<'a>,
{
    let len = match lengths.read_u16::<NativeEndian>() {
        Ok(len) => len as usize,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return fallback,
        Err(e) => return Err(RingbufParseError::IoError(e)),
    };
    let (mut buf, tail) = Option::ok_or(payload.split_at_checked(len), RingbufParseError::TruncatedEvent)?;
    *payload = tail;

    T::from_bytes(&mut buf)
}

pub fn parse_ringbuf_event(mut buf: &[u8]) -> Result<KrsiEvent, RingbufParseError> {
    let ev = read_event_header(&mut buf)?;
    let (mut lengths, mut payload) = buf.split_at_checked(ev.nparams as usize * size_of::<u16>()).ok_or(RingbufParseError::TruncatedEvent)?;

    match ev.evt_type {
        krsi_common::EventType::Open => {
            let name = CString::from(next_field(&mut lengths, &mut payload, Ok(c""))?);
            let fd = next_field(&mut lengths, &mut payload, Ok(0u64))?;
            let file_index = next_field(&mut lengths, &mut payload, Ok(-1i32))?;
            let flags = next_field(&mut lengths, &mut payload, Ok(0u32))?;
            let mode = next_field(&mut lengths, &mut payload, Ok(0u32))?;
            let dev = next_field(&mut lengths, &mut payload, Ok(0u32))?;
            let ino = next_field(&mut lengths, &mut payload, Ok(0u64))?;
            let pid = (ev.tgid_pid >> 32) as u32;
            let tid = (ev.tgid_pid & 0xffffffff) as u32;

            Ok(KrsiEvent {
                tid,
                pid,
                content: KrsiEventContent::Open {
                    fd: fd as i32,
                    name,
                    file_index,
                    flags,
                    mode,
                    dev,
                    ino,
                },
            })
        }
        _ => Err(RingbufParseError::NotYetImplemented)
    }
}
