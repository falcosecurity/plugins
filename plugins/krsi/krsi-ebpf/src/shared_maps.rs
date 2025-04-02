use aya_ebpf::helpers::bpf_get_smp_processor_id;
use aya_ebpf::macros::map;
use aya_ebpf::maps::{Array, RingBuf};
use krsi_common::EventType;

#[map]
// The number of max entries is set, in userspace, to the value of available CPU.
static AUXILIARY_MAPS: Array<crate::auxmap::AuxiliaryMap> = Array::with_max_entries(0, 0);

#[no_mangle]
static BOOT_TIME: u64 = 0;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(128 * 4096, 0); // 128 pages = 256KB

pub fn get_auxiliary_map() -> Option<&'static mut crate::auxmap::AuxiliaryMap> {
    let cpu_id = unsafe {bpf_get_smp_processor_id()};
    AUXILIARY_MAPS.get_ptr_mut(cpu_id).map(|p| unsafe {&mut *p})
}

pub fn get_events_ringbuf() -> &'static RingBuf {
    &EVENTS
}

// TODO(ekoops): move this function elsewhere.
pub fn get_event_num_params(event_type: EventType) -> u8 {
    match event_type.try_into() {
        // TODO(ekoops): try to generate the following numbers automatically.
        Ok(EventType::Open) => 7,
        Ok(EventType::Connect) => 4,
        Ok(EventType::Socket) => 6,
        _ => 0,
    }
}

pub fn get_boot_time() -> u64 {
    unsafe {core::ptr::read_volatile(&BOOT_TIME)}
}
