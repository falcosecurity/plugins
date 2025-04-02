use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;
use crate::FileDescriptor;

#[map]
static CONN_FDS: HashMap<u32, FileDescriptor> = HashMap::with_max_entries(32768, 0);

pub fn get_conn_fds() -> &'static HashMap<u32, FileDescriptor> {
    &CONN_FDS
}
