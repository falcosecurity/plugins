use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy)]
    pub struct FeatureFlags: u8 {
        const IO_URING = 1 << 0;
        const SYSCALLS = 1 << 1;
    }
}

bitflags! {
    #[derive(Clone, Copy)]
    pub struct OpFlags: u8 {
        const OPEN = 1 << 0;
        const CONNECT = 1 << 1;
        const SOCKET = 1 << 2;
        const SYMLINKAT = 1 << 3;
        const LINKAT = 1 << 4;
        const UNLINKAT = 1 << 5;
    }
}
