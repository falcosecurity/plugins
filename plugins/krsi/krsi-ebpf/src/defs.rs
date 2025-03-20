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
