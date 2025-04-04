use crate::vmlinux;

// Definition of MINORBITS, MINORMASK, major and minor funcs taken from `/include/linux/kdev_t.h`
// kernel source tree file.

const MINORBITS: u32 = 20;
const MINORMASK: u32 = (1_u32 << MINORBITS) - 1;

pub fn encode(dev: vmlinux::dev_t) -> vmlinux::dev_t {
    let maj = major(dev);
    let min = minor(dev);
    (min & 0xff) | (maj << 8) | ((min & !0xff) << 12)
}


fn major(dev: vmlinux::dev_t) -> u32 {
    (dev) >> MINORBITS
}

fn minor(dev: vmlinux::dev_t) -> u32 {
    (dev) & MINORMASK
}
