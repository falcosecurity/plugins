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
    let ev = unsafe { read_and_move::<krsi_common::EventHeader>(ptr_mut) };
    match ev.evt_type.try_into() {
        Ok(krsi_common::EventType::Open) => parse_ringbuf_open_event(&ev, ptr_mut),
        _ => Err(()),
    }
}

fn parse_ringbuf_open_event(
    ev: &krsi_common::EventHeader,
    ptr: &mut *const u8,
) -> Result<KrsiEvent, ()> {
    let lengths = unsafe { read_and_move::<[u16; 7]>(ptr) };
    let fd = if lengths[0] != 0 {
        unsafe { read_and_move::<i64>(ptr) }
    } else {
        -1
    };
    let file_index = if lengths[1] != 0 {
        unsafe { read_and_move::<i32>(ptr) }
    } else {
        -1
    };
    let name = unsafe { read_str_and_move(ptr, lengths[2] as usize) };
    let flags = unsafe { read_and_move::<u32>(ptr) };
    let mode = unsafe { read_and_move::<u32>(ptr) };
    let dev = unsafe { read_and_move::<u32>(ptr) };
    let ino = unsafe { read_and_move::<u64>(ptr) };
    let pid = (ev.tgid_pid >> 32) as u32;
    let tid = (ev.tgid_pid & 0xffffffff) as u32;
    Ok(KrsiEvent {
        tid,
        pid,
        content: KrsiEventContent::Open {
            fd: fd as i32,
            file_index,
            name: String::from(name),
            flags,
            mode,
            dev,
            ino,
        },
    })
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
