#![allow(unused)]

/* O_* bits. */

pub const O_ACCMODE: u32 = 0o0000003;
pub const O_RDONLY: u32 = 0o0000000;
pub const O_WRONLY: u32 = 0o0000001;
pub const O_RDWR: u32 = 0o0000002;
pub const O_CREAT: u32 = 0o0000100; // not fcntl
pub const O_EXCL: u32 = 0o0000200; // not fcntl
pub const O_NOCTTY: u32 = 0o0000400; // not fcntl
pub const O_TRUNC: u32 = 0o0001000; // not fcntl
pub const O_APPEND: u32 = 0o0002000;
pub const O_NONBLOCK: u32 = 0o0004000;
pub const O_NDELAY: u32 = O_NONBLOCK;
pub const O_DSYNC: u32 = 0o0010000; // used to be O_SYNC, see below
pub const FASYNC: u32 = 0o0020000; // fcntl, for BSD compatibility

cfg_if::cfg_if! {
      if #[cfg(target_arch = "aarch64")] {
        // `/arch/arm64/include/uapi/asm/fcntl.h` from kernel source tree.
        pub const O_DIRECTORY: u32 = 0o40000; // must be a directory
        pub const O_NOFOLLOW: u32 = 0o100000; // don't follow links
        pub const O_DIRECT: u32 = 0o200000;   // direct disk access hint - currently ignored
        pub const O_LARGEFILE: u32 = 0o400000;
    } else if #[cfg(any(target_arch = "powerpc", target_arch = "powerpc64"))] {
        // `/arch/powerpc/include/uapi/asm/fcntl.h` from kernel source tree.
        pub const O_DIRECTORY: u32 = 0o40000; // must be a directory
        pub const O_NOFOLLOW: u32 = 0o100000; // don't follow links
        pub const O_LARGEFILE: u32 = 0o200000;
        pub const O_DIRECT: u32 = 0o400000; // direct disk access hint
    } else {
        // `/include/uapi/asm-generic/fnctl.h` from kernel source tree.
        pub const O_DIRECT: u32 = 0o0040000; // direct disk access hint
        pub const O_LARGEFILE: u32 = 0o0100000;
        pub const O_DIRECTORY: u32 = 0o0200000; // must be a directory
        pub const O_NOFOLLOW: u32 = 0o0400000;  // don't follow links
    }
}

pub const O_NOATIME: u32 = 01000000;
pub const O_CLOEXEC: u32 = 02000000; // set close_on_exec
pub const __O_SYNC: u32 = 04000000;
pub const O_SYNC: u32 = __O_SYNC | O_DSYNC;
pub const O_PATH: u32 = 010000000;
pub const __O_TMPFILE: u32 = 020000000;

// a horrid kludge trying to make sure that this will fail on old kernels.
pub const O_TMPFILE: u32 = __O_TMPFILE | O_DIRECTORY;
pub const O_TMPFILE_MASK: u32 = __O_TMPFILE | O_DIRECTORY | O_CREAT;

/* File mode flags. */

// `include/linux/fs.h` from kernel source tree.

pub const FMODE_CREATED: u32 = /*(__force fmode_t) */ 0x100000;

/* Chmod modes. */

// `/include/uapi/linux/stat.h` from kernel source tree.

pub const S_IFMT: u32 = 0o0170000;
pub const S_IFSOCK: u32 = 0o140000;
pub const S_IFLNK: u32 = 0o120000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFBLK: u32 = 0o060000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFCHR: u32 = 0o020000;
pub const S_IFIFO: u32 = 0o010000;
pub const S_ISUID: u32 = 0o004000;
pub const S_ISGID: u32 = 0o002000;
pub const S_ISVTX: u32 = 0o001000;

pub const S_IRWXU: u32 = 0o0700;
pub const S_IRUSR: u32 = 0o0400;
pub const S_IWUSR: u32 = 0o0200;
pub const S_IXUSR: u32 = 0o0100;

pub const S_IRWXG: u32 = 0o0070;
pub const S_IRGRP: u32 = 0o0040;
pub const S_IWGRP: u32 = 0o0020;
pub const S_IXGRP: u32 = 0o0010;

pub const S_IRWXO: u32 = 0o0007;
pub const S_IROTH: u32 = 0o0004;
pub const S_IWOTH: u32 = 0o0002;
pub const S_IXOTH: u32 = 0o0001;

/* Address families. */

// `/include/linux/socket.h` from kernel source tree.

pub const AF_UNSPEC: u16 = 0;
pub const AF_UNIX: u16 = 1; // Unix domain sockets
pub const AF_LOCAL: u16 = 1; // POSIX name for AF_UNIX
pub const AF_INET: u16 = 2; // Internet IP Protocol
pub const AF_AX25: u16 = 3; // Amateur Radio AX.25
pub const AF_IPX: u16 = 4; // Novell IPX
pub const AF_APPLETALK: u16 = 5; // AppleTalk DDP
pub const AF_NETROM: u16 = 6; // Amateur Radio NET/ROM
pub const AF_BRIDGE: u16 = 7; // Multiprotocol bridge
pub const AF_ATMPVC: u16 = 8; // ATM PVCs
pub const AF_X25: u16 = 9; // Reserved for X.25 project
pub const AF_INET6: u16 = 10; // IP version 6
pub const AF_ROSE: u16 = 11; // Amateur Radio X.25 PLP
pub const AF_DEC_NET: u16 = 12; // Reserved for DECnet project
pub const AF_NETBEUI: u16 = 13; // Reserved for 802.2LLC project
pub const AF_SECURITY: u16 = 14; // Security callback pseudo AF
pub const AF_KEY: u16 = 15; // PF_KEY key management API
pub const AF_NETLINK: u16 = 16;
pub const AF_ROUTE: u16 = AF_NETLINK; // Alias to emulate 4.4BSD
pub const AF_PACKET: u16 = 17; // Packet family
pub const AF_ASH: u16 = 18; // Ash
pub const AF_ECONET: u16 = 19; // Acorn Econet
pub const AF_ATMSVC: u16 = 20; // ATM SVCs
pub const AF_RDS: u16 = 21; // RDS sockets
pub const AF_SNA: u16 = 22; // Linux SNA Project (nutters!)
pub const AF_IRDA: u16 = 23; // IRDA sockets
pub const AF_PPPOX: u16 = 24; // PPPoX sockets
pub const AF_WANPIPE: u16 = 25; // Wanpipe API Sockets
pub const AF_LLC: u16 = 26; // Linux LLC
pub const AF_IB: u16 = 27; // Native InfiniBand address
pub const AF_MPLS: u16 = 28; // MPLS
pub const AF_CAN: u16 = 29; // Controller Area Network
pub const AF_TIPC: u16 = 30; // TIPC sockets
pub const AF_BLUETOOTH: u16 = 31; // Bluetooth sockets
pub const AF_IUCV: u16 = 32; // IUCV sockets
pub const AF_RXRPC: u16 = 33; // RxRPC sockets
pub const AF_ISDN: u16 = 34; // mISDN sockets
pub const AF_PHONET: u16 = 35; // Phonet sockets
pub const AF_IEEE802154: u16 = 36; // IEEE802154 sockets
pub const AF_CAIF: u16 = 37; // CAIF sockets
pub const AF_ALG: u16 = 38; // Algorithm sockets
pub const AF_NFC: u16 = 39; // NFC sockets
pub const AF_VSOCK: u16 = 40; // vSockets
pub const AF_KCM: u16 = 41; // Kernel Connection Multiplexor
pub const AF_QIPCRTR: u16 = 42; // Qualcomm IPC Router
pub const AF_SMC: u16 = 43; // smc sockets: reserve number for PF_SMC protocol family that reuses AF_INET address family
pub const AF_XDP: u16 = 44; // XDP sockets
pub const AF_MCTP: u16 = 45; // Management component transport protocol
pub const AF_MAX: u16 = 46; // For now...

// Network components sizes.
pub const FAMILY_SIZE: usize = size_of::<u8>();
pub const IPV4_SIZE: usize = size_of::<u32>();
pub const IPV6_SIZE: usize = 16;
pub const PORT_SIZE: usize = size_of::<u16>();
pub const KERNEL_POINTER: usize = size_of::<u64>();

/* Unix socket path. */

// `/include/uapi/linux/un.h` from kernel source tree.

pub const UNIX_PATH_MAX: usize = 108;

/* Errors. */

// FIXME(ekoops): not all architectures are supported by rust. Just take the asm-generic definitions
//  for the moment.
// `/include/uapi/asm-generic/errno.h` from kernel source tree.

pub const EINPROGRESS: i32 = 115;

/* io_uring uapi. */

// `include/uapi/linux/io_uring.h` from kernel source tree.

pub const IORING_FILE_INDEX_ALLOC: u32 = !0;

// `io_uring/io_uring.h` from kernel source tree.
pub const IOU_OK: i32 = 0;

/* Max path size. */

pub const MAX_PATH: u16 = 4096;

/* Types of directory notifications that may be requested. */

// `/include/uapi/linux/fcntl.h` from kernel source tree.
pub const AT_FDCWD: i32 = -100; // Special value for dirfd used to indicate openat should use the current working directory.
