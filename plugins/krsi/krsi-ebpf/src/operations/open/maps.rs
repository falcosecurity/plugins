use aya_ebpf::{macros::map, maps::HashMap};

pub struct Info {
    pub fd_installed: bool,
}

impl Info {
    pub fn new() -> Self {
        Self {
            fd_installed: false,
        }
    }
}

#[map]
static OPEN_INFO: HashMap<u32, Info> = HashMap::with_max_entries(32768, 0);

pub fn get_info_map() -> &'static HashMap<u32, Info> {
    &OPEN_INFO
}
