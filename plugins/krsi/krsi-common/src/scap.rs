// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2025 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#![allow(unused)]

// File flags
pub const PPM_O_NONE: u32 = 0;
pub const PPM_O_RDONLY: u32 = 1 << 0; // Open for reading only
pub const PPM_O_WRONLY: u32 = 1 << 1; // Open for writing only
pub const PPM_O_RDWR: u32 = PPM_O_RDONLY | PPM_O_WRONLY; // Open for reading and writing
pub const PPM_O_CREAT: u32 = 1 << 2; // Create a new file if it doesn't exist.
pub const PPM_O_APPEND: u32 = 1 << 3; // If set, the file offset shall be set to the end of the file prior to each write.
pub const PPM_O_DSYNC: u32 = 1 << 4;
pub const PPM_O_EXCL: u32 = 1 << 5;
pub const PPM_O_NONBLOCK: u32 = 1 << 6;
pub const PPM_O_SYNC: u32 = 1 << 7;
pub const PPM_O_TRUNC: u32 = 1 << 8;
pub const PPM_O_DIRECT: u32 = 1 << 9;
pub const PPM_O_DIRECTORY: u32 = 1 << 10;
pub const PPM_O_LARGEFILE: u32 = 1 << 11;
pub const PPM_O_CLOEXEC: u32 = 1 << 12;
pub const PPM_O_TMPFILE: u32 = 1 << 13;

// Flags added by syscall probe:
pub const PPM_O_F_CREATED: u32 = 1 << 14; // file created during the syscall
pub const PPM_FD_UPPER_LAYER: u32 = 1 << 15; // file is from upper layer
pub const PPM_FD_LOWER_LAYER: u32 = 1 << 16; // file is from upper layer

// File modes.
pub const PPM_S_NONE: u32 = 0;
pub const PPM_S_IXOTH: u32 = 1 << 0;
pub const PPM_S_IWOTH: u32 = 1 << 1;
pub const PPM_S_IROTH: u32 = 1 << 2;
pub const PPM_S_IXGRP: u32 = 1 << 3;
pub const PPM_S_IWGRP: u32 = 1 << 4;
pub const PPM_S_IRGRP: u32 = 1 << 5;
pub const PPM_S_IXUSR: u32 = 1 << 6;
pub const PPM_S_IWUSR: u32 = 1 << 7;
pub const PPM_S_IRUSR: u32 = 1 << 8;
pub const PPM_S_ISVTX: u32 = 1 << 9;
pub const PPM_S_ISGID: u32 = 1 << 10;
pub const PPM_S_ISUID: u32 = 1 << 11;

// Socket families.
pub const PPM_AF_UNSPEC: u8 = 0;
pub const PPM_AF_UNIX: u8 = 1; // Unix domain sockets
pub const PPM_AF_LOCAL: u8 = 1; // POSIX name for PPM_AF_UNIX
pub const PPM_AF_INET: u8 = 2; // Internet IP Protocol
pub const PPM_AF_AX25: u8 = 3; // Amateur Radio AX.25
pub const PPM_AF_IPX: u8 = 4; // Novell IPX
pub const PPM_AF_APPLETALK: u8 = 5; // AppleTalk DDP
pub const PPM_AF_NETROM: u8 = 6; // Amateur Radio NET/ROM
pub const PPM_AF_BRIDGE: u8 = 7; // Multiprotocol bridge
pub const PPM_AF_ATMPVC: u8 = 8; // ATM PVCs
pub const PPM_AF_X25: u8 = 9; // Reserved for X.25 project
pub const PPM_AF_INET6: u8 = 10; // IP version 6
pub const PPM_AF_ROSE: u8 = 11; // Amateur Radio X.25 PLP
pub const PPM_AF_DEC_NET: u8 = 12; // Reserved for DECnet project
pub const PPM_AF_NETBEUI: u8 = 13; // Reserved for 802.2LLC project
pub const PPM_AF_SECURITY: u8 = 14; // Security callback pseudo AF
pub const PPM_AF_KEY: u8 = 15; // PF_KEY key management API
pub const PPM_AF_NETLINK: u8 = 16;
pub const PPM_AF_ROUTE: u8 = PPM_AF_NETLINK; // Alias to emulate 4.4BSD
pub const PPM_AF_PACKET: u8 = 17; // Packet family
pub const PPM_AF_ASH: u8 = 18; // Ash
pub const PPM_AF_ECONET: u8 = 19; // Acorn Econet
pub const PPM_AF_ATMSVC: u8 = 20; // ATM SVCs
pub const PPM_AF_RDS: u8 = 21; // RDS sockets
pub const PPM_AF_SNA: u8 = 22; // Linux SNA Project (nutters!)
pub const PPM_AF_IRDA: u8 = 23; // IRDA sockets
pub const PPM_AF_PPPOX: u8 = 24; // PPPoX sockets
pub const PPM_AF_WANPIPE: u8 = 25; // Wanpipe API Sockets
pub const PPM_AF_LLC: u8 = 26; // Linux LLC
pub const PPM_AF_CAN: u8 = 29; // Controller Area Network
pub const PPM_AF_TIPC: u8 = 30; // TIPC sockets
pub const PPM_AF_BLUETOOTH: u8 = 31; // Bluetooth sockets
pub const PPM_AF_IUCV: u8 = 32; // IUCV sockets
pub const PPM_AF_RXRPC: u8 = 33; // RxRPC sockets
pub const PPM_AF_ISDN: u8 = 34; // mISDN sockets
pub const PPM_AF_PHONET: u8 = 35; // Phonet sockets
pub const PPM_AF_IEEE802154: u8 = 36; // IEEE802154 sockets
pub const PPM_AF_CAIF: u8 = 37; // CAIF sockets
pub const PPM_AF_ALG: u8 = 38; // Algorithm sockets
pub const PPM_AF_NFC: u8 = 39; // NFC sockets

// Dirfd-related flags.
pub const PPM_AT_FDCWD: i32 = -100;

// linkat flags.
pub const PPM_AT_SYMLINK_FOLLOW: i32 = 0x400;
pub const PPM_AT_EMPTY_PATH: i32 = 0x1000;

// unlinkat flags.
pub const PPM_AT_REMOVEDIR: i32 = 0x200;
