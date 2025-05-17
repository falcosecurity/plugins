// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

use std::{
    ffi::{CStr, CString},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use byteorder::{BigEndian, NativeEndian, ReadBytesExt};
use krsi_common::{scap, EventHeader, EventType};
use serde::{Deserialize, Serialize};
use zerocopy::FromBytes as ZcFromBytes;

#[derive(Serialize, Deserialize, Debug)]
pub struct KrsiEvent {
    pub pid: u32,
    pub tid: u32,
    pub content: KrsiEventContent,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum KrsiEventContent {
    Open {
        fd: Option<i64>,
        file_index: Option<i32>,
        name: Option<CString>,
        flags: Option<u32>,
        mode: Option<u32>,
        dev: Option<u32>,
        ino: Option<u64>,
        iou_ret: Option<i64>,
    },
    Socket {
        iou_ret: Option<i64>,
        fd: Option<i64>,
        file_index: Option<i32>,
        domain: Option<u32>,
        type_: Option<u32>,
        protocol: Option<u32>,
    },
    Connect {
        fd: Option<i64>,
        file_index: Option<i32>,
        connection: Option<Connection>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
    Symlinkat {
        target: Option<CString>,
        linkdirfd: Option<i64>,
        linkpath: Option<CString>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
    Linkat {
        olddirfd: Option<i64>,
        oldpath: Option<CString>,
        newdirfd: Option<i64>,
        newpath: Option<CString>,
        flags: Option<u32>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
    Unlinkat {
        dirfd: Option<i64>,
        path: Option<CString>,
        flags: Option<u32>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
    Mkdirat {
        dirfd: Option<i64>,
        path: Option<CString>,
        mode: Option<u32>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum Connection {
    Inet {
        server_addr: IpAddr,
        server_port: u16,
        client_addr: IpAddr,
        client_port: u16,
    },
    Unix {
        src_ptr: u64,
        dst_ptr: u64,
        path: CString,
    },
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            Self::Inet {
                server_addr,
                server_port,
                client_addr,
                client_port,
            } => {
                let s = format!("{client_addr}:{client_port}->{server_addr}:{server_port}");
                f.write_str(&s)
            }
            Self::Unix {
                src_ptr,
                dst_ptr,
                path,
            } => {
                let s_path = path.to_str().unwrap();
                let s = format!("{src_ptr:#x}->{dst_ptr:#x} {s_path}");
                f.write_str(&s)
            }
        }
    }
}

impl KrsiEventContent {
    pub fn fd(&self) -> Option<i64> {
        match &self {
            KrsiEventContent::Open { fd, .. } => *fd,
            KrsiEventContent::Connect { fd, .. } => *fd,
            KrsiEventContent::Socket { fd, .. } => *fd,
            _ => None,
        }
    }

    pub fn file_index(&self) -> Option<i32> {
        match &self {
            KrsiEventContent::Open { file_index, .. } => *file_index,
            KrsiEventContent::Connect { file_index, .. } => *file_index,
            KrsiEventContent::Socket { file_index, .. } => *file_index,
            _ => None,
        }
    }

    pub fn flags(&self) -> Option<u32> {
        match &self {
            KrsiEventContent::Open { flags, .. } => *flags,
            KrsiEventContent::Linkat { flags, .. } => *flags,
            KrsiEventContent::Unlinkat { flags, .. } => *flags,
            _ => None,
        }
    }

    pub fn name(&self) -> Option<CString> {
        match &self {
            KrsiEventContent::Open { name, .. } => name.clone(),
            KrsiEventContent::Connect { connection, .. } => connection
                .as_ref()
                .map(|c| CString::new(c.to_string()).unwrap()),
            _ => None,
        }
    }

    pub fn mode(&self) -> Option<u32> {
        match &self {
            KrsiEventContent::Open { mode, .. } => *mode,
            KrsiEventContent::Mkdirat { mode, .. } => *mode,
            _ => None,
        }
    }

    pub fn dev(&self) -> Option<u32> {
        match &self {
            KrsiEventContent::Open { dev, .. } => *dev,
            _ => None,
        }
    }

    pub fn ino(&self) -> Option<u64> {
        match &self {
            KrsiEventContent::Open { ino, .. } => *ino,
            _ => None,
        }
    }

    pub fn iou_ret(&self) -> Option<i64> {
        match &self {
            KrsiEventContent::Socket { iou_ret, .. } => *iou_ret,
            KrsiEventContent::Connect { iou_ret, .. } => *iou_ret,
            KrsiEventContent::Symlinkat { iou_ret, .. } => *iou_ret,
            KrsiEventContent::Linkat { iou_ret, .. } => *iou_ret,
            KrsiEventContent::Unlinkat { iou_ret, .. } => *iou_ret,
            KrsiEventContent::Mkdirat { iou_ret, .. } => *iou_ret,
            _ => None,
        }
    }

    pub fn domain(&self) -> Option<u32> {
        match &self {
            KrsiEventContent::Socket { domain, .. } => *domain,
            _ => None,
        }
    }

    pub fn r#type(&self) -> Option<u32> {
        match &self {
            KrsiEventContent::Socket { type_, .. } => *type_,
            _ => None,
        }
    }

    pub fn protocol(&self) -> Option<u32> {
        match &self {
            KrsiEventContent::Socket { protocol, .. } => *protocol,
            _ => None,
        }
    }

    pub fn res(&self) -> Option<i64> {
        match &self {
            KrsiEventContent::Connect { res, .. } => *res,
            KrsiEventContent::Symlinkat { res, .. } => *res,
            KrsiEventContent::Linkat { res, .. } => *res,
            KrsiEventContent::Unlinkat { res, .. } => *res,
            KrsiEventContent::Mkdirat { res, .. } => *res,
            _ => None,
        }
    }

    pub fn linkdirfd(&self) -> Option<i64> {
        match &self {
            KrsiEventContent::Symlinkat { linkdirfd, .. } => *linkdirfd,
            _ => None,
        }
    }

    pub fn olddirfd(&self) -> Option<i64> {
        match &self {
            KrsiEventContent::Linkat { olddirfd, .. } => *olddirfd,
            _ => None,
        }
    }

    pub fn dirfd(&self) -> Option<i64> {
        match &self {
            KrsiEventContent::Unlinkat { dirfd, .. } => *dirfd,
            KrsiEventContent::Mkdirat { dirfd, .. } => *dirfd,
            _ => None,
        }
    }

    pub fn newdirfd(&self) -> Option<i64> {
        match &self {
            KrsiEventContent::Linkat { newdirfd, .. } => *newdirfd,
            _ => None,
        }
    }

    pub fn linkpath(&self) -> Option<CString> {
        match &self {
            KrsiEventContent::Symlinkat { linkpath, .. } => linkpath.clone(),
            _ => None,
        }
    }

    pub fn path(&self) -> Option<CString> {
        match &self {
            KrsiEventContent::Unlinkat { path, .. } => path.clone(),
            KrsiEventContent::Mkdirat { path, .. } => path.clone(),
            _ => None,
        }
    }

    pub fn oldpath(&self) -> Option<CString> {
        match &self {
            KrsiEventContent::Linkat { oldpath, .. } => oldpath.clone(),
            _ => None,
        }
    }

    pub fn newpath(&self) -> Option<CString> {
        match &self {
            KrsiEventContent::Linkat { newpath, .. } => newpath.clone(),
            _ => None,
        }
    }

    pub fn target(&self) -> Option<CString> {
        match &self {
            KrsiEventContent::Symlinkat { target, .. } => target.clone(),
            _ => None,
        }
    }

    pub fn server_port(&self) -> Option<u16> {
        match &self {
            KrsiEventContent::Connect { connection, .. } => {
                if let Some(connection) = connection.as_ref() {
                    match connection {
                        Connection::Inet { server_port, .. } => Some(*server_port),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn client_port(&self) -> Option<u16> {
        match &self {
            KrsiEventContent::Connect { connection, .. } => {
                if let Some(connection) = connection.as_ref() {
                    match connection {
                        Connection::Inet { client_port, .. } => Some(*client_port),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn server_addr(&self) -> Option<IpAddr> {
        match &self {
            KrsiEventContent::Connect { connection, .. } => {
                if let Some(connection) = connection.as_ref() {
                    match connection {
                        Connection::Inet { server_addr, .. } => Some(*server_addr),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn client_addr(&self) -> Option<IpAddr> {
        match &self {
            KrsiEventContent::Connect { connection, .. } => {
                if let Some(connection) = connection.as_ref() {
                    match connection {
                        Connection::Inet { client_addr, .. } => Some(*client_addr),
                        _ => None,
                    }
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RingbufParseError {
    #[error("Truncated event")]
    TruncatedEvent,
    #[error("Unexpected null terminator")]
    UnexpectedNulTerminator,
    #[error("Missing null terminator")]
    MissingNulTerminator,
    #[error("Invalid event type {0}")]
    InvalidType(u16),
    #[error("I/O error")]
    IoError(#[from] std::io::Error),
    #[error("Not yet implemented")]
    NotYetImplemented,
}

trait FromBytes<'a>: Sized {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, RingbufParseError>;
}

macro_rules! gen_from_bytes_int_impl {
    ($typ:ident) => {
        paste::paste! {
            impl FromBytes<'_> for $typ {
                fn from_bytes(buf: &mut &[u8]) -> Result<Self, RingbufParseError> {
                    Ok(buf.[< read_ $typ >]::<NativeEndian>()?)
                }
            }
        }
    };
}

gen_from_bytes_int_impl!(i64);
gen_from_bytes_int_impl!(u64);
gen_from_bytes_int_impl!(i32);
gen_from_bytes_int_impl!(u32);

impl<'a> FromBytes<'a> for &'a CStr {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, RingbufParseError> {
        CStr::from_bytes_until_nul(buf).map_err(|_| RingbufParseError::MissingNulTerminator)
    }
}

impl<'a> FromBytes<'a> for Connection {
    fn from_bytes(buf: &mut &'a [u8]) -> Result<Self, RingbufParseError> {
        let family = buf.read_u8().map_err(RingbufParseError::IoError)?;
        match family {
            scap::PPM_AF_INET => parse_inet_connection(buf).map_err(RingbufParseError::IoError),
            scap::PPM_AF_INET6 => parse_inet6_connection(buf).map_err(RingbufParseError::IoError),
            scap::PPM_AF_UNIX => parse_unix_connection(buf),
            _ => Err(RingbufParseError::NotYetImplemented),
        }
    }
}

fn parse_inet_connection(buf: &mut &[u8]) -> Result<Connection, std::io::Error> {
    let client_addr = IpAddr::V4(Ipv4Addr::from(buf.read_u32::<BigEndian>()?));
    let client_port = buf.read_u16::<NativeEndian>()?;
    let server_addr = IpAddr::V4(Ipv4Addr::from(buf.read_u32::<BigEndian>()?));
    let server_port = buf.read_u16::<NativeEndian>()?;
    Ok(Connection::Inet {
        server_addr,
        server_port,
        client_addr,
        client_port,
    })
}

fn parse_inet6_connection(buf: &mut &[u8]) -> Result<Connection, std::io::Error> {
    let client_addr = IpAddr::V6(Ipv6Addr::from(buf.read_u128::<BigEndian>()?));
    let client_port = buf.read_u16::<NativeEndian>()?;
    let server_addr = IpAddr::V6(Ipv6Addr::from(buf.read_u128::<BigEndian>()?));
    let server_port = buf.read_u16::<NativeEndian>()?;
    Ok(Connection::Inet {
        server_addr,
        server_port,
        client_addr,
        client_port,
    })
}

fn parse_unix_connection(buf: &mut &[u8]) -> Result<Connection, RingbufParseError> {
    let src_ptr = buf.read_u64::<NativeEndian>()?;
    let dst_ptr = buf.read_u64::<NativeEndian>()?;
    let path = if buf.is_empty() {
        c"".into()
    } else {
        // Use CString::new because buf must not contain any internal null byte.
        CString::new(*buf).map_err(|_| RingbufParseError::UnexpectedNulTerminator)?
    };
    Ok(Connection::Unix {
        src_ptr,
        dst_ptr,
        path,
    })
}

/// Reads the next value from the provided `values` slice, taking its length from the provided
/// `lengths` slice. Returns None if the value length is determined to be 0. Updates the provided
/// `lengths` and `values` slices by removing the read bytes.
fn read_next_field<'a, T>(
    lengths: &mut &[u8],
    values: &mut &'a [u8],
) -> Result<Option<T>, RingbufParseError>
where
    T: FromBytes<'a>,
{
    let len = match lengths.read_u16::<NativeEndian>() {
        Ok(len) => len as usize,
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(RingbufParseError::TruncatedEvent)
        }
        Err(e) => return Err(RingbufParseError::IoError(e)),
    };
    if len == 0 {
        return Ok(None);
    }
    let (mut buf, tail) = Option::ok_or(
        values.split_at_checked(len),
        RingbufParseError::TruncatedEvent,
    )?;
    *values = tail;
    Ok(Some(T::from_bytes(&mut buf)?))
}

pub fn parse_ringbuf_event(mut buf: &[u8]) -> Result<KrsiEvent, RingbufParseError> {
    let evt_hdr = read_event_header(&mut buf)?;
    let evt_type = evt_hdr.evt_type.get();
    let evt_type =
        EventType::try_from(evt_type).map_err(|_| RingbufParseError::InvalidType(evt_type))?;
    let (mut lengths, mut values) = buf
        .split_at_checked(evt_hdr.nparams.get() as usize * size_of::<u16>())
        .ok_or(RingbufParseError::TruncatedEvent)?;
    let content = match evt_type {
        EventType::Open => parse_rb_open_event_content(&mut lengths, &mut values),
        EventType::Connect => parse_rb_connect_event_content(&mut lengths, &mut values),
        EventType::Socket => parse_rb_socket_event_content(&mut lengths, &mut values),
        EventType::Symlinkat => parse_rb_symlinkat_event_content(&mut lengths, &mut values),
        EventType::Linkat => parse_rb_linkat_event_content(&mut lengths, &mut values),
        EventType::Unlinkat => parse_rb_unlinkat_event_content(&mut lengths, &mut values),
        EventType::Mkdirat => parse_rb_mkdirat_event_content(&mut lengths, &mut values),
        _ => Err(RingbufParseError::NotYetImplemented),
    }?;
    let tgid_pid = evt_hdr.tgid_pid.get();
    let pid = (tgid_pid >> 32) as u32;
    let tid = (tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent { pid, tid, content })
}

fn read_event_header(buf: &mut &[u8]) -> Result<EventHeader, RingbufParseError> {
    if buf.len() < size_of::<EventHeader>() {
        return Err(RingbufParseError::TruncatedEvent);
    }
    // The following cannot fail as we are providing a slice with the exact same size of an
    // EventHeader.
    let evt_hdr = EventHeader::read_from_bytes(&buf[..size_of::<EventHeader>()]).unwrap();
    *buf = &buf[size_of::<EventHeader>()..];
    Ok(evt_hdr)
}

fn parse_rb_open_event_content(
    lengths: &mut &[u8],
    values: &mut &[u8],
) -> Result<KrsiEventContent, RingbufParseError> {
    let name = read_next_field::<&CStr>(lengths, values)?.map(CString::from);
    let fd = read_next_field(lengths, values)?;
    let file_index = read_next_field(lengths, values)?;
    let flags = read_next_field(lengths, values)?;
    let mode = read_next_field(lengths, values)?;
    let dev = read_next_field(lengths, values)?;
    let ino = read_next_field(lengths, values)?;
    let iou_ret = read_next_field(lengths, values)?;
    Ok(KrsiEventContent::Open {
        fd,
        file_index,
        name,
        flags,
        mode,
        dev,
        ino,
        iou_ret,
    })
}

fn parse_rb_connect_event_content(
    lengths: &mut &[u8],
    values: &mut &[u8],
) -> Result<KrsiEventContent, RingbufParseError> {
    let connection = read_next_field(lengths, values)?;
    let iou_ret = read_next_field(lengths, values)?;
    let res = read_next_field(lengths, values)?;
    let fd = read_next_field(lengths, values)?;
    let file_index = read_next_field(lengths, values)?;
    Ok(KrsiEventContent::Connect {
        fd,
        file_index,
        res,
        iou_ret,
        connection,
    })
}

fn parse_rb_socket_event_content(
    lengths: &mut &[u8],
    values: &mut &[u8],
) -> Result<KrsiEventContent, RingbufParseError> {
    let iou_ret = read_next_field(lengths, values)?;
    let fd = read_next_field(lengths, values)?;
    let file_index = read_next_field(lengths, values)?;
    let domain = read_next_field(lengths, values)?;
    let type_ = read_next_field(lengths, values)?;
    let protocol = read_next_field(lengths, values)?;
    Ok(KrsiEventContent::Socket {
        iou_ret,
        fd,
        file_index,
        domain,
        type_,
        protocol,
    })
}

fn parse_rb_symlinkat_event_content(
    lengths: &mut &[u8],
    values: &mut &[u8],
) -> Result<KrsiEventContent, RingbufParseError> {
    let target = read_next_field::<&CStr>(lengths, values)?.map(CString::from);
    let linkdirfd = read_next_field(lengths, values)?;
    let linkpath = read_next_field::<&CStr>(lengths, values)?.map(CString::from);
    let res = read_next_field(lengths, values)?;
    let iou_ret = read_next_field(lengths, values)?;
    Ok(KrsiEventContent::Symlinkat {
        target,
        linkdirfd,
        linkpath,
        res,
        iou_ret,
    })
}

fn parse_rb_linkat_event_content(
    lengths: &mut &[u8],
    values: &mut &[u8],
) -> Result<KrsiEventContent, RingbufParseError> {
    let olddirfd = read_next_field(lengths, values)?;
    let oldpath = read_next_field::<&CStr>(lengths, values)?.map(CString::from);
    let newdirfd = read_next_field(lengths, values)?;
    let newpath = read_next_field::<&CStr>(lengths, values)?.map(CString::from);
    let flags = read_next_field(lengths, values)?;
    let res = read_next_field(lengths, values)?;
    let iou_ret = read_next_field(lengths, values)?;
    Ok(KrsiEventContent::Linkat {
        olddirfd,
        oldpath,
        newdirfd,
        newpath,
        flags,
        res,
        iou_ret,
    })
}

fn parse_rb_unlinkat_event_content(
    lengths: &mut &[u8],
    values: &mut &[u8],
) -> Result<KrsiEventContent, RingbufParseError> {
    let dirfd = read_next_field(lengths, values)?;
    let path = read_next_field::<&CStr>(lengths, values)?.map(CString::from);
    let flags = read_next_field(lengths, values)?;
    let res = read_next_field(lengths, values)?;
    let iou_ret = read_next_field(lengths, values)?;
    Ok(KrsiEventContent::Unlinkat {
        dirfd,
        path,
        flags,
        res,
        iou_ret,
    })
}

fn parse_rb_mkdirat_event_content(
    lengths: &mut &[u8],
    values: &mut &[u8],
) -> Result<KrsiEventContent, RingbufParseError> {
    let dirfd = read_next_field(lengths, values)?;
    let path = read_next_field::<&CStr>(lengths, values)?.map(CString::from);
    let mode = read_next_field(lengths, values)?;
    let res = read_next_field(lengths, values)?;
    let iou_ret = read_next_field(lengths, values)?;
    Ok(KrsiEventContent::Mkdirat {
        dirfd,
        path,
        mode,
        res,
        iou_ret,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sock_tuple_to_connection_ipv4() {
        let mut sock_tuple: &[u8] = &[
            0x02, 0xac, 0x28, 0x6f, 0xde, 0x31, 0xd4, 0x8e, 0xfb, 0x6f, 0x93, 0xbb, 0x01,
        ];
        let conn = Connection::from_bytes(&mut sock_tuple).unwrap();
        let expected = Connection::Inet {
            server_addr: "142.251.111.147".parse().unwrap(),
            server_port: 443,
            client_addr: "172.40.111.222".parse().unwrap(),
            client_port: 54321,
        };
        assert_eq!(conn, expected);
        assert_eq!(
            conn.to_string(),
            "172.40.111.222:54321->142.251.111.147:443"
        );
    }

    #[test]
    fn test_sock_tuple_to_connection_ipv6() {
        let mut sock_tuple: &[u8] = &[
            0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x31, 0xd4, 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0xbb, 0x01,
        ];
        let conn = Connection::from_bytes(&mut sock_tuple).unwrap();
        let expected = Connection::Inet {
            server_addr: "2001:4860:4860::8888".parse().unwrap(),
            server_port: 443,
            client_addr: "::1".parse().unwrap(),
            client_port: 54321,
        };
        assert_eq!(conn, expected);
        assert_eq!(conn.to_string(), "::1:54321->2001:4860:4860::8888:443");
    }

    #[test]
    fn test_sock_tuple_to_connection_unix() {
        let mut sock_tuple: &[u8] = &[
            0x01, 0x0f, 0x8d, 0x75, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x8d, 0x75, 0x9c, 0x00,
            0x00, 0x00, 0x00, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d,
            0x2e, 0x73, 0x6f, 0x63, 0x6b,
        ];
        let conn = Connection::from_bytes(&mut sock_tuple).unwrap();
        let expected = Connection::Unix {
            src_ptr: 0x9c758d0f,
            dst_ptr: 0x9c758d0a,
            path: c"/tmp/stream.sock".into(),
        };
        assert_eq!(conn, expected);
    }
}
