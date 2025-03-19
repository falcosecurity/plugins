use aya_ebpf::bindings::BPF_RB_FORCE_WAKEUP;
use aya_ebpf::cty::c_uchar;
use aya_ebpf::helpers::{
    bpf_get_current_pid_tgid, bpf_ktime_get_boot_ns, bpf_probe_read_kernel_str_bytes,
};
use krsi_common::{EventHeader, EventType};

// Event maximum size.
const MAX_EVENT_SIZE: u64 = 64 * 1024;

// Paramater maximum size.
const MAX_PARAM_SIZE: u64 = MAX_EVENT_SIZE - 1;

const AUXILIARY_MAP_SIZE: usize = 128 * 1024;

pub struct AuxiliaryMap {
    // raw space to save our variable-size event.
    pub data: [u8; AUXILIARY_MAP_SIZE],
    // position of the first empty byte in the `data` buffer.
    pub payload_pos: u64,
    // position of the first empty slot into the lengths array of the event.
    pub lenghts_pos: u8,
    // event type we want to send to userspace.
    pub event_type: u16,
}

impl AuxiliaryMap {
    unsafe fn get_event_header_mut_ref(&mut self) -> &mut EventHeader {
        &mut *self.data.as_mut_ptr().cast::<EventHeader>()
    }

    pub unsafe fn preload_event_header(&mut self, event_type: EventType) {
        let evt_hdr = self.get_event_header_mut_ref();
        let nparams = crate::maps::get_event_num_params(event_type);
        evt_hdr.nparams = nparams as u32;
        evt_hdr.ts = crate::maps::get_boot_time() + bpf_ktime_get_boot_ns();
        evt_hdr.tid = bpf_get_current_pid_tgid() & 0xffffffff;
        evt_hdr.evt_type = event_type;
        self.payload_pos =
            (size_of::<EventHeader>() + (nparams as usize) * size_of::<u16>()) as u64;
        self.lenghts_pos = size_of::<EventHeader>() as u8;
        self.event_type = event_type as u16;
    }

    pub unsafe fn finalize_event_header(&mut self) {
        let payload_pos = self.payload_pos as u32;
        let evt_hdr = self.get_event_header_mut_ref();
        evt_hdr.len = payload_pos;
    }

    pub unsafe fn store_param<T: Copy>(&mut self, param: T) {
        self.push(param);
        self.push_param_len(size_of::<T>() as u16);
    }

    /// This helper stores the charbuf pointed by `charbuf_pointer` into the auxmap. We read until
    /// we find a `\0`, if the charbuf length is greater than `max_len_to_read`, we read up to
    /// `max_len_to_read-1` bytes and add the `\0`.
    pub unsafe fn store_charbuf_param(
        &mut self,
        charbuf_ptr: *const c_uchar,
        max_len_to_read: u16,
    ) -> Result<u16, i64> {
        let mut charbuf_len = 0_u16;
        if !charbuf_ptr.is_null() {
            charbuf_len = self.push_charbuf(charbuf_ptr, max_len_to_read as usize)?;
        }
        self.push_param_len(charbuf_len);
        Ok(charbuf_len)
    }

    // Helper used to please the verifier during reading operations like `bpf_probe_read_str()`.
    fn data_safe_access(x: u64) -> usize {
        (x & MAX_PARAM_SIZE) as usize
    }

    unsafe fn push<T>(&mut self, value: T)
    where
        T: Copy,
    {
        let pos = Self::data_safe_access(self.payload_pos);
        self.data
            .as_mut_ptr()
            .byte_add(pos)
            .cast::<T>()
            .write_unaligned(value);
        self.payload_pos += size_of::<T>() as u64;
    }

    unsafe fn push_param_len(&mut self, value: u16) {
        let pos = Self::data_safe_access(self.lenghts_pos as u64);
        self.data
            .as_mut_ptr()
            .byte_add(pos)
            .cast::<u16>()
            .write_unaligned(value);
        self.lenghts_pos = self.lenghts_pos + size_of::<u16>() as u8;
    }

    /// Try to push the char buffer pointed by `charbuf_ptr` into the underlying buffer.
    /// The maximum length of the char buffer can be at most `max_len_to_read`. In case of success,
    /// returns the number of written bytes. If the char buffer is empty, an empty string
    /// (corresponding to `\0`, which has length of 1) is pushed: this means that in case of
    /// success, a strictly positive integer is returned.
    unsafe fn push_charbuf(
        &mut self,
        charbuf_ptr: *const c_uchar,
        max_len_to_read: usize,
    ) -> Result<u16, i64> {
        let pos = Self::data_safe_access(self.payload_pos);
        let limit = pos + max_len_to_read;
        let written_str = bpf_probe_read_kernel_str_bytes(charbuf_ptr, &mut self.data[pos..limit])?;
        let written_bytes = written_str.len();
        if written_bytes == 0 {
            // Push '\0' and returns 1 as number of written bytes.
            self.push(0_u8);
            return Ok(1);
        }
        self.payload_pos += written_bytes as u64;
        Ok(written_bytes as u16)
    }
    pub unsafe fn submit_event(&self) {
        if self.payload_pos > MAX_EVENT_SIZE {
            // TODO: account for drop.
            return;
        }

        let _ = crate::maps::get_events_ringbuf()
            .output(self.data.as_ref(), BPF_RB_FORCE_WAKEUP as u64);
    }
}
