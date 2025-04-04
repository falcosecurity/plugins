use aya_ebpf::macros::map;
use aya_ebpf::maps::HashMap;

#[map]
static LINKAT_IOU_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(32768, 0);

pub fn get_iou_pids_map() -> &'static HashMap<u32, u32> {
    &LINKAT_IOU_PIDS
}
