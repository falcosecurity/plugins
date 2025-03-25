use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[map]
static SOCK_TIDS: HashMap<u32, u32> = HashMap::with_max_entries(32768, 0);

#[map]
static SOCK_PTRS: HashMap<u32, usize> = HashMap::with_max_entries(32768, 0);

#[map]
static SOCK_RES: HashMap<SockPtrTgid, u32> = HashMap::with_max_entries(32768, 0);

pub fn get_sock_tids_map() -> &'static HashMap<u32, u32> {
    &SOCK_TIDS
}

pub fn get_sock_ptrs_map() -> &'static HashMap<u32, usize> {
    &SOCK_PTRS
}

#[repr(C)]
pub struct SockPtrTgid {
    pub sock_ptr: usize,
    pub tgid: u32,
}

pub fn get_sock_res_amp() -> &'static HashMap<SockPtrTgid, u32> {
    &SOCK_RES
}
