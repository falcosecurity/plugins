use krsi_ebpf_core::ffi;

// Definition of MINORBITS, MINORMASK, major and minor funcs taken from `/include/linux/kdev_t.h`
// kernel source tree file.

const MINORBITS: u32 = 20;
const MINORMASK: u32 = (1_u32 << MINORBITS) - 1;

pub fn encode(dev: ffi::dev_t) -> ffi::dev_t {
    let maj = major(dev);
    let min = minor(dev);
    (min & 0xff) | (maj << 8) | ((min & !0xff) << 12)
}

fn major(dev: ffi::dev_t) -> u32 {
    (dev) >> MINORBITS
}

fn minor(dev: ffi::dev_t) -> u32 {
    (dev) & MINORMASK
}
