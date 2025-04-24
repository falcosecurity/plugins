use aya_ebpf::{macros::map, maps::HashMap};

pub struct Info {
    pub is_iou: bool,
    pub flags: Option<i32>,
}

impl Info {
    pub fn new(is_iou: bool, flags: Option<i32>) -> Self {
        Self { is_iou, flags }
    }
}

#[map]
static UNLINKAT_INFO: HashMap<u32, Info> = HashMap::with_max_entries(32768, 0);

pub fn get_info_map() -> &'static HashMap<u32, Info> {
    &UNLINKAT_INFO
}
