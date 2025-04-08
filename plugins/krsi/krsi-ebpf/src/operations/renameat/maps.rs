use aya_ebpf::{macros::map, maps::HashMap};

#[map]
static RENAMEAT_IOU_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(32768, 0);

pub fn get_iou_pids_map() -> &'static HashMap<u32, u32> {
    &RENAMEAT_IOU_PIDS
}
