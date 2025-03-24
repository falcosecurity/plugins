#![allow(unused)]

// File flags
const PPM_O_NONE: u32 = 0;
const PPM_O_RDONLY: u32 = 1 << 0; // Open for reading only
const PPM_O_WRONLY: u32 = 1 << 1; // Open for writing only
const PPM_O_RDWR: u32 = PPM_O_RDONLY | PPM_O_WRONLY; // Open for reading and writing
const PPM_O_CREAT: u32 = 1 << 2; // Create a new file if it doesn't exist.
const PPM_O_APPEND: u32 = 1 << 3; // If set, the file offset shall be set to the end of the file prior to each write.
const PPM_O_DSYNC: u32 = 1 << 4;
const PPM_O_EXCL: u32 = 1 << 5;
const PPM_O_NONBLOCK: u32 = 1 << 6;
const PPM_O_SYNC: u32 = 1 << 7;
const PPM_O_TRUNC: u32 = 1 << 8;
const PPM_O_DIRECT: u32 = 1 << 9;
const PPM_O_DIRECTORY: u32 = 1 << 10;
const PPM_O_LARGEFILE: u32 = 1 << 11;
const PPM_O_CLOEXEC: u32 = 1 << 12;
const PPM_O_TMPFILE: u32 = 1 << 13;

// Flags added by syscall probe:
pub const PPM_O_F_CREATED: u32 = 1 << 14; // file created during the syscall
pub const PPM_FD_UPPER_LAYER: u32 = 1 << 15; // file is from upper layer
pub const PPM_FD_LOWER_LAYER: u32 = 1 << 16; // file is from upper layer

// File modes.
const PPM_S_NONE: u32 = 0;
const PPM_S_IXOTH: u32 = 1 << 0;
const PPM_S_IWOTH: u32 = 1 << 1;
const PPM_S_IROTH: u32 = 1 << 2;
const PPM_S_IXGRP: u32 = 1 << 3;
const PPM_S_IWGRP: u32 = 1 << 4;
const PPM_S_IRGRP: u32 = 1 << 5;
const PPM_S_IXUSR: u32 = 1 << 6;
const PPM_S_IWUSR: u32 = 1 << 7;
const PPM_S_IRUSR: u32 = 1 << 8;
const PPM_S_ISVTX: u32 = 1 << 9;
const PPM_S_ISGID: u32 = 1 << 10;
const PPM_S_ISUID: u32 = 1 << 11;

use crate::defs;

pub fn encode_open_flags(flags: u32) -> u32 {
    let mut res = 0_u32;

    match flags & (defs::O_RDONLY | defs::O_WRONLY | defs::O_RDWR) {
        defs::O_WRONLY => res |= PPM_O_WRONLY,
        defs::O_RDWR => res |= PPM_O_RDWR,
        _ /* O_RDONLY */ => res |= PPM_O_RDONLY,
    }

    if (flags & defs::O_CREAT) != 0 {
        res |= PPM_O_CREAT;
    }
    if (flags & defs::O_TMPFILE) != 0 {
        res |= PPM_O_TMPFILE;
    }

    if (flags & defs::O_APPEND) != 0 {
        res |= PPM_O_APPEND;
    }

    if (flags & defs::O_DSYNC) != 0 {
        res |= PPM_O_DSYNC;
    }

    if (flags & defs::O_EXCL) != 0 {
        res |= PPM_O_EXCL;
    }

    if (flags & defs::O_NONBLOCK) != 0 {
        res |= PPM_O_NONBLOCK;
    }

    if (flags & defs::O_SYNC) != 0 {
        res |= PPM_O_SYNC;
    }

    if (flags & defs::O_TRUNC) != 0 {
        res |= PPM_O_TRUNC;
    }

    if (flags & defs::O_DIRECT) != 0 {
        res |= PPM_O_DIRECT;
    }

    if (flags & defs::O_DIRECTORY) != 0 {
        res |= PPM_O_DIRECTORY;
    }

    if (flags & defs::O_LARGEFILE) != 0 {
        res |= PPM_O_LARGEFILE;
    }

    if (flags & defs::O_CLOEXEC) != 0 {
        res |= PPM_O_CLOEXEC;
    }

    res
}

pub fn encode_fmode_created(mode: u32) -> u32 {
    if (mode & defs::FMODE_CREATED) != 0 {
        PPM_O_F_CREATED
    } else {
        0
    }
}

pub fn encode_open_mode(flags: u32, mode: u32) -> u32 {
    let mut res = 0_u32;

    if (flags & (defs::O_CREAT | defs::O_TMPFILE)) == 0 {
        return res;
    }

    if (mode & defs::S_IRUSR) != 0 {
        res |= PPM_S_IRUSR;
    }

    if (mode & defs::S_IWUSR) != 0 {
        res |= PPM_S_IWUSR;
    }

    if (mode & defs::S_IXUSR) != 0 {
        res |= PPM_S_IXUSR;
    }

    // PPM_S_IRWXU == S_IRUSR | S_IWUSR | S_IXUSR

    if (mode & defs::S_IRGRP) != 0 {
        res |= PPM_S_IRGRP;
    }

    if (mode & defs::S_IWGRP) != 0 {
        res |= PPM_S_IWGRP;
    }

    if (mode & defs::S_IXGRP) != 0 {
        res |= PPM_S_IXGRP;
    }

    // PPM_S_IRWXG == S_IRGRP | S_IWGRP | S_IXGRP

    if (mode & defs::S_IROTH) != 0 {
        res |= PPM_S_IROTH;
    }

    if (mode & defs::S_IWOTH) != 0 {
        res |= PPM_S_IWOTH;
    }

    if (mode & defs::S_IXOTH) != 0 {
        res |= PPM_S_IXOTH;
    }

    // PPM_S_IRWXO == S_IROTH | S_IWOTH | S_IXOTH

    if (mode & defs::S_ISUID) != 0 {
        res |= PPM_S_ISUID;
    }

    if (mode & defs::S_ISGID) != 0 {
        res |= PPM_S_ISGID;
    }

    if (mode & defs::S_ISVTX) != 0 {
        res |= PPM_S_ISVTX;
    }

    res
}
