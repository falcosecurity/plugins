use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct KrsiEvent {
    pub tgid_tid: u64,
    pub content: KrsiEventContent,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum KrsiEventContent {
    Open {
        fd: u32,
        name: String,
        flags: u32,
        mode: u32,
        dev: u32,
        ino: u64,
    },
}

pub fn parse_ringbuf_event(buf: &[u8]) -> Result<KrsiEvent, ()> {
    let mut ptr = buf.as_ptr();
    let ev = unsafe { read_and_move::<krsi_common::EventHeader>(&mut ptr) };
    let mut name_len = 0;
    for i in 0..ev.nparams {
        let len = unsafe { read_and_move::<u16>(&mut ptr) };
        if i == 1 {
            name_len = len;
        }
    }
    match ev.evt_type.try_into() {
        Ok(krsi_common::EventType::FdInstall) => {
            let fd = unsafe { read_and_move::<i64>(&mut ptr) };
            let name = unsafe { read_str_and_move(&mut ptr, name_len as usize) };
            let flags = unsafe { read_and_move::<u32>(&mut ptr) };
            let mode = unsafe { read_and_move::<u32>(&mut ptr) };
            let dev = unsafe { read_and_move::<u32>(&mut ptr) };
            let ino = unsafe { read_and_move::<u64>(&mut ptr) };
            Ok(KrsiEvent {
                tgid_tid: ev.tgid_pid,
                content: KrsiEventContent::Open {
                    fd: fd as u32,
                    name: String::from(name),
                    flags,
                    mode,
                    dev,
                    ino,
                },
            })
        }
        _ => Err(()),
    }
}

unsafe fn read_and_move<T>(ptr: &mut *const u8) -> T {
    let v = (*ptr).cast::<T>().read_unaligned();
    *ptr = (*ptr).byte_add(size_of::<T>());
    v
}

unsafe fn read_str_and_move(ptr: &mut *const u8, len: usize) -> &'static str {
    if len == 0 {
        ""
    } else {
        // TODO better check for null character here
        let s = unsafe { std::str::from_utf8_unchecked(std::slice::from_raw_parts(*ptr, len - 1)) };
        *ptr = (*ptr).byte_add(len);
        s
    }
}
