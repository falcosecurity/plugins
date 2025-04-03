use crate::FileDescriptor;
use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[derive(Clone, Copy)]
pub struct ConnInfo {
    pub file_descriptor: FileDescriptor,
    pub is_iou: bool,
    pub socktuple_len: u16,
}

impl ConnInfo {
    pub fn new(file_descriptor: FileDescriptor, is_iou: bool) -> Self {
        Self {
            file_descriptor,
            is_iou,
            socktuple_len: 0,
        }
    }
}

#[map]
static CONN_INFO: HashMap<u32, ConnInfo> = HashMap::with_max_entries(32768, 0);

pub fn get_conn_info_map() -> &'static HashMap<u32, ConnInfo> {
    &CONN_INFO
}
