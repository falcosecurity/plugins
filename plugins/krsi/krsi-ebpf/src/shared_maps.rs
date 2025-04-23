use aya_ebpf::{
    helpers::bpf_get_smp_processor_id,
    macros::map,
    maps::{Array, RingBuf},
};
use krsi_common::flags::{FeatureFlags, OpFlags};

#[map]
// The number of max entries is set, in userspace, to the value of available CPU.
static AUXILIARY_MAPS: Array<crate::auxmap::AuxiliaryMap> = Array::with_max_entries(0, 0);

#[no_mangle]
static BOOT_TIME: u64 = 0;

#[no_mangle]
static FEATURE_FLAGS: u8 = 0;
#[no_mangle]
static OP_FLAGS: u64 = 0;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(128 * 4096, 0); // 128 pages = 256KB

pub fn get_auxiliary_map() -> Option<&'static mut crate::auxmap::AuxiliaryMap> {
    let cpu_id = unsafe { bpf_get_smp_processor_id() };
    AUXILIARY_MAPS
        .get_ptr_mut(cpu_id)
        .map(|p| unsafe { &mut *p })
}

pub fn get_events_ringbuf() -> &'static RingBuf {
    &EVENTS
}

pub fn get_boot_time() -> u64 {
    unsafe { core::ptr::read_volatile(&BOOT_TIME) }
}

fn get_enabled_feature_flags() -> FeatureFlags {
    FeatureFlags::from_bits_truncate(unsafe { core::ptr::read_volatile(&FEATURE_FLAGS) })
}

fn get_enabled_op_flags() -> OpFlags {
    OpFlags::from_bits_truncate(unsafe { core::ptr::read_volatile(&OP_FLAGS) })
}

pub fn is_support_enabled(feature_flags: FeatureFlags, op_flags: OpFlags) -> bool {
    let enabled_op_flags = get_enabled_op_flags();
    let enabled_feature_flags = get_enabled_feature_flags();
    enabled_feature_flags.contains(feature_flags) && enabled_op_flags.contains(op_flags)
}
