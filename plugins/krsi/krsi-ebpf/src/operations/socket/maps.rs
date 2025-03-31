use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use crate::FileDescriptor;

#[map]
static SOCK_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(32768, 0);

#[map]
static SOCK_PTRS: HashMap<u32, usize> = HashMap::with_max_entries(32768, 0);

#[repr(C)]
#[repr(packed)]
pub struct SockPtrTgid {
    pub sock_ptr: usize,
    pub tgid: u32,
}

impl SockPtrTgid {
    pub fn new(sock_ptr: usize, tgid: u32) -> Self {
        Self { sock_ptr, tgid }
    }
}

#[map]
static SOCK_RES: HashMap<SockPtrTgid, FileDescriptor> = HashMap::with_max_entries(32768, 0);

pub fn get_sock_pids_map() -> &'static HashMap<u32, u32> {
    &SOCK_PIDS
}

pub fn get_sock_ptrs_map() -> &'static HashMap<u32, usize> {
    &SOCK_PTRS
}

pub fn get_sock_res_amp() -> &'static HashMap<SockPtrTgid, FileDescriptor> {
    &SOCK_RES
}
