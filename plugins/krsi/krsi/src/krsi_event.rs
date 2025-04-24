use std::{
    ffi::CString,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use krsi_common::{scap, EventHeader};
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
        fd: Option<i64>,
        file_index: Option<i32>,
        name: Option<String>,
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
        target: Option<String>,
        linkdirfd: Option<i64>,
        linkpath: Option<String>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
    Linkat {
        olddirfd: Option<i64>,
        oldpath: Option<String>,
        newdirfd: Option<i64>,
        newpath: Option<String>,
        flags: Option<u32>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
    Unlinkat {
        dirfd: Option<i64>,
        path: Option<String>,
        flags: Option<u32>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
    Mkdirat {
        dirfd: Option<i64>,
        path: Option<String>,
        mode: Option<u32>,
        res: Option<i64>,
        iou_ret: Option<i64>,
    },
}

#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub enum Connection {
    Inet {
        server_addr: std::net::IpAddr,
        server_port: u16,
        client_addr: std::net::IpAddr,
        client_port: u16,
    },
    Unix {
        src_ptr: u64,
        dst_ptr: u64,
        addr: CString,
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
                addr,
            } => {
                let s_addr = addr.to_str().unwrap();
                let s = format!("{src_ptr:#x}->{dst_ptr:#x} {s_addr}");
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

    pub fn name(&self) -> Option<String> {
        match &self {
            KrsiEventContent::Open { name, .. } => name.clone(),
            KrsiEventContent::Connect { connection, .. } => {
                connection.as_ref().map(|c| c.to_string())
            }
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

    pub fn type_(&self) -> Option<u32> {
        match &self {
            KrsiEventContent::Socket { type_, .. } => *type_,
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

    pub fn linkpath(&self) -> Option<String> {
        match &self {
            KrsiEventContent::Symlinkat { linkpath, .. } => linkpath.clone(),
            _ => None,
        }
    }

    pub fn path(&self) -> Option<String> {
        match &self {
            KrsiEventContent::Unlinkat { path, .. } => path.clone(),
            KrsiEventContent::Mkdirat { path, .. } => path.clone(),
            _ => None,
        }
    }

    pub fn oldpath(&self) -> Option<String> {
        match &self {
            KrsiEventContent::Linkat { oldpath, .. } => oldpath.clone(),
            _ => None,
        }
    }

    pub fn newpath(&self) -> Option<String> {
        match &self {
            KrsiEventContent::Linkat { newpath, .. } => newpath.clone(),
            _ => None,
        }
    }

    pub fn target(&self) -> Option<String> {
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

unsafe fn read_and_move<T>(ptr: &mut *const u8) -> T {
    let v = (*ptr).cast::<T>().read_unaligned();
    *ptr = (*ptr).byte_add(size_of::<T>());
    v
}

unsafe fn read_str_and_move(ptr: &mut *const u8, len: usize) -> &'static str {
    let real_len = len - 1;
    let s = if real_len == 0 {
        ""
    } else {
        unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(*ptr, real_len)) }
    };
    *ptr = (*ptr).byte_add(len);
    s
}

unsafe fn read_u8_slice_and_move(ptr: &mut *const u8, len: usize) -> &'static [u8] {
    let s = unsafe { std::slice::from_raw_parts(*ptr, len) };
    *ptr = (*ptr).byte_add(len);
    s
}

pub fn parse_ringbuf_event(buf: &[u8]) -> Result<KrsiEvent, String> {
    let mut ptr = buf.as_ptr();
    let ptr_mut = &mut ptr;
    let ev = unsafe { read_and_move::<EventHeader>(ptr_mut) };
    match ev.evt_type.try_into() {
        Ok(krsi_common::EventType::Open) => parse_ringbuf_open_event(&ev, ptr_mut),
        Ok(krsi_common::EventType::Connect) => parse_ringbuf_connect_event(&ev, ptr_mut),
        Ok(krsi_common::EventType::Socket) => parse_socket_event(&ev, ptr_mut),
        Ok(krsi_common::EventType::Symlinkat) => parse_symlinkat_event(&ev, ptr_mut),
        Ok(krsi_common::EventType::Linkat) => parse_linkat_event(&ev, ptr_mut),
        Ok(krsi_common::EventType::Unlinkat) => parse_unlinkat_event(&ev, ptr_mut),
        Ok(krsi_common::EventType::Mkdirat) => parse_mkdirat_event(&ev, ptr_mut),
        _ => Err("event type not implemented".into()),
    }
}

fn parse_ringbuf_open_event(ev: &EventHeader, ptr: &mut *const u8) -> Result<KrsiEvent, String> {
    let lengths = unsafe { read_and_move::<[u16; 8]>(ptr) };
    let mut fd: Option<i64> = None;
    let mut file_index: Option<i32> = None;
    let mut flags: Option<u32> = None;
    let mut mode: Option<u32> = None;
    let mut dev: Option<u32> = None;
    let mut ino: Option<u64> = None;
    let mut iou_ret: Option<i64> = None;
    let name: Option<String> = if lengths[0] != 0 {
        Some(unsafe { read_str_and_move(ptr, lengths[0] as usize) }.into())
    } else {
        None
    };
    if lengths[1] != 0 {
        fd = Some(unsafe { read_and_move::<i64>(ptr) });
    }
    if lengths[2] != 0 {
        file_index = Some(unsafe { read_and_move::<i32>(ptr) });
    }
    if lengths[3] != 0 {
        flags = Some(unsafe { read_and_move::<u32>(ptr) });
    }
    if lengths[4] != 0 {
        mode = Some(unsafe { read_and_move::<u32>(ptr) });
    }
    if lengths[5] != 0 {
        dev = Some(unsafe { read_and_move::<u32>(ptr) });
    }
    if lengths[6] != 0 {
        ino = Some(unsafe { read_and_move::<u64>(ptr) });
    }
    if lengths[7] != 0 {
        iou_ret = Some(unsafe { read_and_move::<i64>(ptr) });
    }
    let pid = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        tid,
        pid,
        content: KrsiEventContent::Open {
            fd,
            file_index,
            name,
            flags,
            mode,
            dev,
            ino,
            iou_ret,
        },
    })
}

fn socktuple_to_connection(socktuple: &[u8]) -> Result<Connection, String> {
    let family = socktuple[0];
    match family {
        scap::PPM_AF_INET => {
            let socktuple: &[u8; 13] =
                socktuple.try_into().or(Err("socktuple buffer too small"))?;
            let cb = &socktuple[1..5];
            let client_port = u16::from_le_bytes(socktuple[5..7].try_into().unwrap());
            let sb = &socktuple[7..11];
            let server_port = u16::from_le_bytes(socktuple[11..13].try_into().unwrap());
            let server_addr = IpAddr::V4(Ipv4Addr::new(sb[0], sb[1], sb[2], sb[3]));
            let client_addr = IpAddr::V4(Ipv4Addr::new(cb[0], cb[1], cb[2], cb[3]));
            Ok(Connection::Inet {
                server_addr,
                server_port,
                client_addr,
                client_port,
            })
        }
        scap::PPM_AF_INET6 => {
            let socktuple: &[u8; 37] =
                socktuple.try_into().or(Err("socktuple buffer too small"))?;
            let cb: &[u8; 16] = &socktuple[1..17].try_into().unwrap();
            let client_port = u16::from_le_bytes(socktuple[17..19].try_into().unwrap());
            let sb: &[u8; 16] = &socktuple[19..35].try_into().unwrap();
            let server_port = u16::from_le_bytes(socktuple[35..37].try_into().unwrap());
            let server_addr = IpAddr::V6(Ipv6Addr::new(
                u16::from_be_bytes(sb[0..2].try_into().unwrap()),
                u16::from_be_bytes(sb[2..4].try_into().unwrap()),
                u16::from_be_bytes(sb[4..6].try_into().unwrap()),
                u16::from_be_bytes(sb[6..8].try_into().unwrap()),
                u16::from_be_bytes(sb[8..10].try_into().unwrap()),
                u16::from_be_bytes(sb[10..12].try_into().unwrap()),
                u16::from_be_bytes(sb[12..14].try_into().unwrap()),
                u16::from_be_bytes(sb[14..16].try_into().unwrap()),
            ));
            let client_addr = IpAddr::V6(Ipv6Addr::new(
                u16::from_be_bytes(cb[0..2].try_into().unwrap()),
                u16::from_be_bytes(cb[2..4].try_into().unwrap()),
                u16::from_be_bytes(cb[4..6].try_into().unwrap()),
                u16::from_be_bytes(cb[6..8].try_into().unwrap()),
                u16::from_be_bytes(cb[8..10].try_into().unwrap()),
                u16::from_be_bytes(cb[10..12].try_into().unwrap()),
                u16::from_be_bytes(cb[12..14].try_into().unwrap()),
                u16::from_be_bytes(cb[14..16].try_into().unwrap()),
            ));
            Ok(Connection::Inet {
                server_addr,
                server_port,
                client_addr,
                client_port,
            })
        }
        scap::PPM_AF_UNIX => {
            let src_ptr = u64::from_le_bytes(
                socktuple[1..9]
                    .try_into()
                    .or(Err("socktuple buffer too small"))?,
            );
            let dst_ptr = u64::from_le_bytes(
                socktuple[9..17]
                    .try_into()
                    .or(Err("socktuple buffer too small"))?,
            );
            let addr_buf = &socktuple[17..];
            let addr: CString = if addr_buf.is_empty() {
                c"".into()
            } else {
                let nul_pos = addr_buf
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(addr_buf.len());
                let without_null = &addr_buf[..nul_pos];
                CString::new(without_null).or(Err("could not convert unix addr string"))?
            };

            Ok(Connection::Unix {
                src_ptr,
                dst_ptr,
                addr,
            })
        }
        _ => Err("invalid or not implemented".into()),
    }
}

fn parse_ringbuf_connect_event(ev: &EventHeader, ptr: &mut *const u8) -> Result<KrsiEvent, String> {
    let lengths = unsafe { read_and_move::<[u16; 5]>(ptr) };
    let mut socktuple: Option<&[u8]> = None;
    let mut iou_ret: Option<i64> = None;
    let mut res: Option<i64> = None;
    let mut fd: Option<i64> = None;
    let mut file_index: Option<i32> = None;
    if lengths[0] != 0 {
        socktuple = Some(unsafe { read_u8_slice_and_move(ptr, lengths[0] as usize) })
    }
    if lengths[1] != 0 {
        iou_ret = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    if lengths[2] != 0 {
        res = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    if lengths[3] != 0 {
        fd = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    if lengths[4] != 0 {
        file_index = Some(unsafe { read_and_move::<i32>(ptr) })
    }
    let pid = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        tid,
        pid,
        content: KrsiEventContent::Connect {
            fd,
            file_index,
            res,
            iou_ret,
            connection: socktuple.and_then(|s| socktuple_to_connection(s).ok()),
        },
    })
}

fn parse_socket_event(ev: &EventHeader, ptr: &mut *const u8) -> Result<KrsiEvent, String> {
    let lengths = unsafe { read_and_move::<[u16; 6]>(ptr) };
    let mut iou_ret: Option<i64> = None;
    let mut fd: Option<i64> = None;
    let mut file_index: Option<i32> = None;
    let mut domain: Option<u32> = None;
    let mut type_: Option<u32> = None;
    let mut protocol: Option<u32> = None;

    if lengths[0] != 0 {
        iou_ret = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    if lengths[1] != 0 {
        fd = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    if lengths[2] != 0 {
        file_index = Some(unsafe { read_and_move::<i32>(ptr) })
    }
    if lengths[3] != 0 {
        domain = Some(unsafe { read_and_move::<u32>(ptr) })
    }
    if lengths[4] != 0 {
        type_ = Some(unsafe { read_and_move::<u32>(ptr) })
    }
    if lengths[5] != 0 {
        protocol = Some(unsafe { read_and_move::<u32>(ptr) })
    }

    let pid = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        pid,
        tid,
        content: KrsiEventContent::Socket {
            iou_ret,
            fd,
            file_index,
            domain,
            type_,
            protocol,
        },
    })
}

fn parse_symlinkat_event(ev: &EventHeader, ptr: &mut *const u8) -> Result<KrsiEvent, String> {
    let lengths = unsafe { read_and_move::<[u16; 5]>(ptr) };
    let mut linkdirfd: Option<i64> = None;
    let mut res: Option<i64> = None;
    let mut iou_ret: Option<i64> = None;
    let target: Option<String> = if lengths[0] != 0 {
        Some(unsafe { read_str_and_move(ptr, lengths[0] as usize) }.into())
    } else {
        None
    };
    if lengths[1] != 0 {
        linkdirfd = Some(unsafe { read_and_move::<i64>(ptr) });
    }
    let linkpath: Option<String> = if lengths[2] != 0 {
        Some(unsafe { read_str_and_move(ptr, lengths[2] as usize) }.into())
    } else {
        None
    };
    if lengths[3] != 0 {
        res = Some(unsafe { read_and_move::<i64>(ptr) });
    }
    if lengths[4] != 0 {
        iou_ret = Some(unsafe { read_and_move::<i64>(ptr) });
    }

    let pid: u32 = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        pid,
        tid,
        content: KrsiEventContent::Symlinkat {
            target,
            linkdirfd,
            linkpath: linkpath,
            res,
            iou_ret,
        },
    })
}

fn parse_linkat_event(ev: &EventHeader, ptr: &mut *const u8) -> Result<KrsiEvent, String> {
    let lengths = unsafe { read_and_move::<[u16; 7]>(ptr) };
    let mut olddirfd: Option<i64> = None;
    let mut newdirfd: Option<i64> = None;
    let mut flags: Option<u32> = None;
    let mut res: Option<i64> = None;
    let mut iou_ret: Option<i64> = None;
    if lengths[0] != 0 {
        olddirfd = Some(unsafe { read_and_move::<i64>(ptr) });
    }
    let oldpath: Option<String> = if lengths[1] != 0 {
        Some(unsafe { read_str_and_move(ptr, lengths[1] as usize) }.into())
    } else {
        None
    };
    if lengths[2] != 0 {
        newdirfd = Some(unsafe { read_and_move::<i64>(ptr) });
    }
    let newpath: Option<String> = if lengths[3] != 0 {
        Some(unsafe { read_str_and_move(ptr, lengths[3] as usize).into() })
    } else {
        None
    };
    if lengths[4] != 0 {
        flags = Some(unsafe { read_and_move::<u32>(ptr) })
    }
    if lengths[5] != 0 {
        res = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    if lengths[6] != 0 {
        iou_ret = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    let pid: u32 = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        pid,
        tid,
        content: KrsiEventContent::Linkat {
            olddirfd,
            oldpath,
            newdirfd,
            newpath,
            flags,
            res,
            iou_ret,
        },
    })
}

fn parse_unlinkat_event(ev: &EventHeader, ptr: &mut *const u8) -> Result<KrsiEvent, String> {
    let lengths = unsafe { read_and_move::<[u16; 5]>(ptr) };
    let mut dirfd: Option<i64> = None;
    let mut flags: Option<u32> = None;
    let mut res: Option<i64> = None;
    let mut iou_ret: Option<i64> = None;

    if lengths[0] != 0 {
        dirfd = Some(unsafe { read_and_move::<i64>(ptr) });
    }
    let path: Option<String> = if lengths[1] != 0 {
        Some(unsafe { read_str_and_move(ptr, lengths[1] as usize).into() })
    } else {
        None
    };
    if lengths[2] != 0 {
        flags = Some(unsafe { read_and_move::<u32>(ptr) })
    }
    if lengths[3] != 0 {
        res = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    if lengths[4] != 0 {
        iou_ret = Some(unsafe { read_and_move::<i64>(ptr) })
    }

    let pid: u32 = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        pid,
        tid,
        content: KrsiEventContent::Unlinkat {
            dirfd,
            path,
            flags,
            res,
            iou_ret,
        },
    })
}

fn parse_mkdirat_event(ev: &EventHeader, ptr: &mut *const u8) -> Result<KrsiEvent, String> {
    let lengths = unsafe { read_and_move::<[u16; 5]>(ptr) };
    let mut dirfd: Option<i64> = None;
    let mut mode: Option<u32> = None;
    let mut res: Option<i64> = None;
    let mut iou_ret: Option<i64> = None;

    if lengths[0] != 0 {
        dirfd = Some(unsafe { read_and_move::<i64>(ptr) });
    }
    let path: Option<String> = if lengths[1] != 0 {
        Some(unsafe { read_str_and_move(ptr, lengths[1] as usize).into() })
    } else {
        None
    };
    if lengths[2] != 0 {
        mode = Some(unsafe { read_and_move::<u32>(ptr) })
    }
    if lengths[3] != 0 {
        res = Some(unsafe { read_and_move::<i64>(ptr) })
    }
    if lengths[4] != 0 {
        iou_ret = Some(unsafe { read_and_move::<i64>(ptr) })
    }

    let pid: u32 = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        pid,
        tid,
        content: KrsiEventContent::Mkdirat {
            dirfd,
            path,
            mode,
            res,
            iou_ret,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socktuple_to_connection_ipv4() {
        let socktuple: &[u8] = &[
            0x02, 0xac, 0x28, 0x6f, 0xde, 0x31, 0xd4, 0x8e, 0xfb, 0x6f, 0x93, 0xbb, 0x01,
        ];
        let conn = socktuple_to_connection(&socktuple).unwrap();
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
    fn test_socktuple_to_connection_ipv6() {
        let socktuple: &[u8] = &[
            0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x31, 0xd4, 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88, 0xbb, 0x01,
        ];
        let conn = socktuple_to_connection(&socktuple).unwrap();
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
    fn test_socktuple_to_connection_unix() {
        let socktuple: &[u8] = &[
            0x01, 0x0f, 0x8d, 0x75, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x8d, 0x75, 0x9c, 0x00,
            0x00, 0x00, 0x00, 0x2f, 0x74, 0x6d, 0x70, 0x2f, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d,
            0x2e, 0x73, 0x6f, 0x63, 0x6b,
        ];
        let conn = socktuple_to_connection(&socktuple).unwrap();
        let expected = Connection::Unix {
            src_ptr: 0x9c758d0f,
            dst_ptr: 0x9c758d0a,
            addr: c"/tmp/stream.sock".into(),
        };
        assert_eq!(conn, expected);
    }
}
