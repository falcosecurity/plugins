#![no_std]
#![allow(clippy::len_without_is_empty)]

#[inline]
fn bpf_probe_read_kernel<T>(ptr: *const T) -> Result<T, i64> {
    #[cfg(target_arch = "bpf")]
    unsafe {
        aya_ebpf::helpers::bpf_probe_read_kernel(ptr)
    }
    #[cfg(not(target_arch = "bpf"))]
    unsafe {
        Ok(core::ptr::read(ptr))
    }
}

pub mod ffi {
    #![allow(non_upper_case_globals)]
    #![allow(non_camel_case_types)]
    #![allow(non_snake_case)]
    #![allow(dead_code)]

    include!(concat!(env!("OUT_DIR"), "/core_helpers.rs"));
}
