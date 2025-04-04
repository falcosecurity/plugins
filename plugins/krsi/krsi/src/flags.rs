use bitflags::bitflags;

bitflags! {
    pub struct FeatureFlags: u8 {
        const ENABLE_IO_URING_SUPPORT = 1 << 0;
        const ENABLE_SYSCALLS_SUPPORT = 1 << 1;
    }
}