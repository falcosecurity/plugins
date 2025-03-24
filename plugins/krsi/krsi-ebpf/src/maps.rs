use aya_ebpf::helpers::bpf_get_smp_processor_id;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, HashMap, RingBuf};
use krsi_common::EventType;

#[map]
static OPEN_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(32768, 0);

#[map]
// The number of max entries is set, in userspace, to the value of available CPU.
static AUXILIARY_MAPS: Array<crate::auxmap::AuxiliaryMap> = Array::with_max_entries(0, 0);

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(128 * 4096, 0); // 128 pages = 256KB

pub unsafe fn get_auxiliary_map() -> Option<&'static mut crate::auxmap::AuxiliaryMap> {
    // TODO: 64 is the maximum number of entry. Remove it once we have the right number of auxiliary maps.
    let cpu_id = (bpf_get_smp_processor_id() % 64) as u32;
    AUXILIARY_MAPS.get_ptr_mut(cpu_id).map(|p| &mut *p)
}

pub fn get_events_ringbuf() -> &'static RingBuf {
    &EVENTS
}

pub fn get_open_pids_map() -> &'static HashMap<u32, u32> {
    &OPEN_PIDS
}

pub fn get_event_num_params(event_type: EventType) -> u8 {
    match event_type.try_into() {
        // TODO: this should become 6 once we have also the other parameters
        Ok(EventType::FdInstall) => 6, // TODO: try to generate it automatically
        _ => 0,
    }
}

pub fn get_boot_time() -> u64 {
    0 // TODO: implement
}
