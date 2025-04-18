use aya_ebpf::{macros::map, maps::HashMap};

use crate::FileDescriptor;

#[map]
static BIND_FDS: HashMap<u32, FileDescriptor> = HashMap::with_max_entries(32768, 0);

pub fn get_file_descriptors_map() -> &'static HashMap<u32, FileDescriptor> {
    &BIND_FDS
}
