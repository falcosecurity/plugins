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
        name: String,
        flags: u32,
        mode: u32,
        dev: u32,
        ino: u64,
    },
}

pub fn parse_ringbuf_event(buf: &[u8]) -> Result<KrsiEvent, ()> {
    let mut ptr = buf.as_ptr();
    let ptr_mut = &mut ptr;
    let ev = unsafe { read_and_move::<EventHeader>(ptr_mut) };
    match ev.evt_type.try_into() {
        Ok(krsi_common::EventType::Open) => parse_ringbuf_open_event(&ev, ptr_mut),
        _ => Err(()),
    }
}

fn parse_ringbuf_open_event(ev: &EventHeader, ptr: &mut *const u8) -> Result<KrsiEvent, ()> {
    let lengths = unsafe { read_and_move::<[u16; 7]>(ptr) };
    let mut name: Option<&str> = None;
    let mut fd: Option<i64> = None;
    let mut file_index: Option<i32> = None;
    let mut flags: Option<u32> = None;
    let mut mode: Option<u32> = None;
    let mut dev: Option<u32> = None;
    let mut ino: Option<u64> = None;
    if lengths[0] != 0 {
        name = Some(unsafe { read_str_and_move(ptr, lengths[0] as usize) });
    }
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
    let pid = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        tid,
        pid,
        content: KrsiEventContent::Open {
            fd: fd.unwrap_or(-1) as i32,
            file_index: file_index.unwrap_or(-1),
            name: name.unwrap_or("").to_string(),
            flags: flags.unwrap_or(0),
            mode: mode.unwrap_or(0),
            dev: dev.unwrap_or(0),
            ino: ino.unwrap_or(0),
        },
    })
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
