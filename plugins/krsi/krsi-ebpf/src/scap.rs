use crate::defs;
use krsi_common::scap;

pub fn encode_open_flags(flags: u32) -> u32 {
    let mut res = 0_u32;

    match flags & (defs::O_RDONLY | defs::O_WRONLY | defs::O_RDWR) {
        defs::O_WRONLY => res |= scap::PPM_O_WRONLY,
        defs::O_RDWR => res |= scap::PPM_O_RDWR,
        _ /* O_RDONLY */ => res |= scap::PPM_O_RDONLY,
    }

    if (flags & defs::O_CREAT) != 0 {
        res |= scap::PPM_O_CREAT;
    }
    if (flags & defs::O_TMPFILE) != 0 {
        res |= scap::PPM_O_TMPFILE;
    }

    if (flags & defs::O_APPEND) != 0 {
        res |= scap::PPM_O_APPEND;
    }

    if (flags & defs::O_DSYNC) != 0 {
        res |= scap::PPM_O_DSYNC;
    }

    if (flags & defs::O_EXCL) != 0 {
        res |= scap::PPM_O_EXCL;
    }

    if (flags & defs::O_NONBLOCK) != 0 {
        res |= scap::PPM_O_NONBLOCK;
    }

    if (flags & defs::O_SYNC) != 0 {
        res |= scap::PPM_O_SYNC;
    }

    if (flags & defs::O_TRUNC) != 0 {
        res |= scap::PPM_O_TRUNC;
    }

    if (flags & defs::O_DIRECT) != 0 {
        res |= scap::PPM_O_DIRECT;
    }

    if (flags & defs::O_DIRECTORY) != 0 {
        res |= scap::PPM_O_DIRECTORY;
    }

    if (flags & defs::O_LARGEFILE) != 0 {
        res |= scap::PPM_O_LARGEFILE;
    }

    if (flags & defs::O_CLOEXEC) != 0 {
        res |= scap::PPM_O_CLOEXEC;
    }

    res
}

pub fn encode_fmode_created(mode: u32) -> u32 {
    if (mode & defs::FMODE_CREATED) != 0 {
        scap::PPM_O_F_CREATED
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
        res |= scap::PPM_S_IRUSR;
    }

    if (mode & defs::S_IWUSR) != 0 {
        res |= scap::PPM_S_IWUSR;
    }

    if (mode & defs::S_IXUSR) != 0 {
        res |= scap::PPM_S_IXUSR;
    }

    // PPM_S_IRWXU == S_IRUSR | S_IWUSR | S_IXUSR

    if (mode & defs::S_IRGRP) != 0 {
        res |= scap::PPM_S_IRGRP;
    }

    if (mode & defs::S_IWGRP) != 0 {
        res |= scap::PPM_S_IWGRP;
    }

    if (mode & defs::S_IXGRP) != 0 {
        res |= scap::PPM_S_IXGRP;
    }

    // PPM_S_IRWXG == S_IRGRP | S_IWGRP | S_IXGRP

    if (mode & defs::S_IROTH) != 0 {
        res |= scap::PPM_S_IROTH;
    }

    if (mode & defs::S_IWOTH) != 0 {
        res |= scap::PPM_S_IWOTH;
    }

    if (mode & defs::S_IXOTH) != 0 {
        res |= scap::PPM_S_IXOTH;
    }

    // PPM_S_IRWXO == S_IROTH | S_IWOTH | S_IXOTH

    if (mode & defs::S_ISUID) != 0 {
        res |= scap::PPM_S_ISUID;
    }

    if (mode & defs::S_ISGID) != 0 {
        res |= scap::PPM_S_ISGID;
    }

    if (mode & defs::S_ISVTX) != 0 {
        res |= scap::PPM_S_ISVTX;
    }

    res
}

pub fn encode_socket_family(family: u16) -> u8 {
    match family {
        defs::AF_INET => scap::PPM_AF_INET,
        defs::AF_INET6 => scap::PPM_AF_INET6,
        defs::AF_UNIX => scap::PPM_AF_UNIX,
        defs::AF_NETLINK /* same value of defs::AF_ROUTE */ => scap::PPM_AF_NETLINK,
        defs::AF_PACKET => scap::PPM_AF_PACKET,
        defs::AF_UNSPEC => scap::PPM_AF_UNSPEC,
        defs::AF_AX25 => scap::PPM_AF_AX25,
        defs::AF_IPX => scap::PPM_AF_IPX,
        defs::AF_APPLETALK => scap::PPM_AF_APPLETALK,
        defs::AF_NETROM => scap::PPM_AF_NETROM,
        defs::AF_BRIDGE => scap::PPM_AF_BRIDGE,
        defs::AF_ATMPVC => scap::PPM_AF_ATMPVC,
        defs::AF_X25 => scap::PPM_AF_X25,
        defs::AF_ROSE => scap::PPM_AF_ROSE,
        defs::AF_DEC_NET => scap::PPM_AF_DEC_NET,
        defs::AF_NETBEUI => scap::PPM_AF_NETBEUI,
        defs::AF_SECURITY => scap::PPM_AF_SECURITY,
        defs::AF_KEY => scap::PPM_AF_KEY,
        defs::AF_ASH => scap::PPM_AF_ASH,
        defs::AF_ECONET => scap::PPM_AF_ECONET,
        defs::AF_ATMSVC => scap::PPM_AF_ATMSVC,
        defs::AF_RDS => scap::PPM_AF_RDS,
        defs::AF_SNA => scap::PPM_AF_SNA,
        defs::AF_IRDA => scap::PPM_AF_IRDA,
        defs::AF_PPPOX => scap::PPM_AF_PPPOX,
        defs::AF_WANPIPE => scap::PPM_AF_WANPIPE,
        defs::AF_LLC => scap::PPM_AF_LLC,
        defs::AF_CAN => scap::PPM_AF_CAN,
        defs::AF_TIPC => scap::PPM_AF_TIPC,
        defs::AF_BLUETOOTH => scap::PPM_AF_BLUETOOTH,
        defs::AF_IUCV => scap::PPM_AF_IUCV,
        defs::AF_RXRPC => scap::PPM_AF_RXRPC,
        defs::AF_ISDN => scap::PPM_AF_ISDN,
        defs::AF_PHONET => scap::PPM_AF_PHONET,
        defs::AF_IEEE802154 => scap::PPM_AF_IEEE802154,
        defs::AF_CAIF => scap::PPM_AF_CAIF,
        defs::AF_ALG => scap::PPM_AF_ALG,
        defs::AF_NFC => scap::PPM_AF_NFC,
        _ => scap::PPM_AF_UNSPEC,
    }
}
