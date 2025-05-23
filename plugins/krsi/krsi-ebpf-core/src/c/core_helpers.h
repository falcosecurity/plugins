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

#ifndef __CORE_HELPERS_H__
#define __CORE_HELPERS_H__

#if defined(__bpf__)
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

// bpf_core_type_size definition.
#if defined(__bpf__)
    // The following is taken from `https://github.com/libbpf/libbpf/blob/master/src/bpf_core_read.h`.
    /* second argument to __builtin_preserve_type_info() built-in */
    enum bpf_type_info_kind {
        BPF_TYPE_EXISTS = 0,		/* type existence in target kernel */
        BPF_TYPE_SIZE = 1,		/* type size in target kernel */
        BPF_TYPE_MATCHES = 2,		/* type match in target kernel */
    };
    #define ___bpf_typeof(type) ((typeof(type) *) 0)
    #define bpf_core_type_size(type) __builtin_preserve_type_info(*___bpf_typeof(type), BPF_TYPE_SIZE)
#else
    #define bpf_core_type_size(type) 0
#endif

typedef long long unsigned int u64;
typedef unsigned int u32;
typedef int s32;
typedef unsigned short u16;
typedef char u8;

#define inline __attribute__((always_inline))

// Taken from 6.13.
typedef u32 dev_t;

// Taken from 6.13.
struct super_block {
    dev_t s_dev;
    u64 s_magic;
};

// Taken from 6.13.
struct inode {
	struct super_block *i_sb;
	u64 i_ino;
};

// Taken from 6.13.
struct qstr {
	union {
		struct {
			u32 hash;
			u32 len;
		};
		u64 hash_len;
	};
	const unsigned char *name;
};

// Taken from 6.13.
struct dentry {
	struct qstr d_name;
	struct inode *d_inode;
	struct super_block *d_sb;
};

// Taken from 6.13.
struct path {
	struct dentry *dentry;
};

// Taken from 6.13.
struct file {
    u32 f_mode;
    void *private_data;
    u32 f_flags;
    struct inode *f_inode;
    struct path f_path;
};

// Taken from 6.13.
struct in6_addr {
    union {
        u8 u6_addr8[16];
        u16 u6_addr16[8];
        u32 u6_addr32[4];
    } in6_u;
};

// Taken from 6.13.
struct sock_common {
    u32 skc_daddr;
    u16 skc_family;
    u16 skc_dport;
    struct in6_addr skc_v6_daddr;
};

// Taken from 6.13.
struct sock {
    struct sock_common __sk_common;
};

// Taken from 6.13.
struct socket {
    struct sock *sk;
};

// Taken from 6.13.
struct ipv6_pinfo {
	struct in6_addr saddr;
};

// Taken from 6.13.
struct inet_sock {
    struct ipv6_pinfo *pinet6;
    u32 inet_saddr;
    u16 inet_sport;
};

// Taken from 6.13.
struct in_addr {
    u32 s_addr;
};

// Taken from 6.13.
struct sockaddr_in {
    u16 sin_port;
    struct in_addr sin_addr;
};

struct sockaddr_in6 {
    u16 sin6_port;
    struct in6_addr sin6_addr;
};

#define UNIX_PATH_MAX	108
// Taken from 6.13.
struct sockaddr_un {
    unsigned char sun_path[UNIX_PATH_MAX];
};

// Taken from 6.13.
struct unix_address {
    s32 len;
    struct sockaddr_un name[];
};

// Taken from 6.13.
struct unix_sock {
	struct unix_address	*addr;
    struct sock *peer;
};

// Taken from 6.13.
struct filename {
    char *name;
};

// Taken from 6.13.
struct io_cqe {
    s32 res;
    union {
        u32	flags;
        s32	fd;
    };
};

// Taken from 6.13.
struct io_cmd_data {
    struct file *file;
};

// Taken from 6.13.
struct sockaddr {
    u16 sa_family;
};

// Taken from 6.13.
struct io_async_msghdr {
    struct sockaddr addr;
};

// Taken from 6.13.
struct io_kiocb {
    union {
        struct file *file;
        struct io_cmd_data cmd;
    };
    u64 flags;
    struct io_cqe cqe;
    void *async_data;
};

// Taken from 6.13.
struct io_rename {
    s32 old_dfd;
    s32 new_dfd;
    struct filename *oldpath;
    struct filename *newpath;
    s32 flags;
};

// Taken from 6.13.
struct io_unlink {
	s32 dfd;
	s32 flags;
	struct filename *filename;
};

// Taken from 6.13.
struct io_socket {
	s32 domain;
	s32 type;
	s32 protocol;
	s32 flags;
	u32 file_slot;
};

// Taken from 6.13.
struct io_bind {
    s32 addr_len;
};

inline u32 *file_f_mode(struct file *file) {
	return &file->f_mode;
}

inline void **file_private_data(struct file *file) {
	return &file->private_data;
}

inline u32 *file_f_flags(struct file *file) {
	return &file->f_flags;
}

inline struct inode **file_f_inode(struct file *file) {
	return &file->f_inode;
}

inline struct path *file_f_path(struct file *file) {
	return &file->f_path;
}

inline struct super_block **inode_i_sb(struct inode *inode) {
	return &inode->i_sb;
}

inline u64 *inode_i_ino(struct inode *inode) {
	return &inode->i_ino;
}

inline struct dentry **inode_upper_dentry(struct inode *inode) {
    unsigned long inode_size = bpf_core_type_size(struct inode);
    if(!inode_size) {
        return 0;
    }
    return (struct dentry**) ((char *)inode + inode_size);
}

inline dev_t *super_block_s_dev(struct super_block *sb) {
	return &sb->s_dev;
}

inline u64 *super_block_s_magic(struct super_block *sb) {
	return &sb->s_magic;
}

inline struct dentry **path_dentry(struct path *path) {
	return &path->dentry;
}

inline struct qstr *dentry_d_name(struct dentry *dentry) {
	return &dentry->d_name;
}

inline struct inode **dentry_d_inode(struct dentry *dentry) {
	return &dentry->d_inode;
}

inline struct super_block **dentry_d_sb(struct dentry *dentry) {
	return &dentry->d_sb;
}

inline struct sock **socket_sk(struct socket *sock) {
    return &sock->sk;
}

inline struct sock_common *sock___sk_common(struct sock *sk) {
    return &sk->__sk_common;
}

inline u32 *sock_common_skc_daddr(struct sock_common *skc) {
    return &skc->skc_daddr;
}

inline u16 *sock_common_skc_family(struct sock_common *skc) {
    return &skc->skc_family;
}

inline u16 *sock_common_skc_dport(struct sock_common *skc) {
    return &skc->skc_dport;
}

inline u32 (*in6_addr_in6_u(struct in6_addr *addr))[4] {
    return &addr->in6_u.u6_addr32;
}

inline struct in6_addr *sock_common_skc_v6_daddr(struct sock_common *skc) {
    return &skc->skc_v6_daddr;
}

inline struct ipv6_pinfo **inet_sock_pinet6(struct inet_sock *sk) {
    return &sk->pinet6;
}

inline struct in6_addr *ipv6_pinfo_saddr(struct ipv6_pinfo *pinet6) {
    return &pinet6->saddr;
}

inline u32 *inet_sock_inet_saddr(struct inet_sock *sk) {
    return &sk->inet_saddr;
}

inline u16 *inet_sock_inet_sport(struct inet_sock *sk) {
    return &sk->inet_sport;
}

inline s32 *unix_address_len(struct unix_address *addr) {
    return &addr->len;
}

inline struct sockaddr_un (*unix_address_name(struct unix_address *addr))[] {
    return &addr->name;
}

inline struct unix_address **unix_sock_addr(struct unix_sock *sk) {
    return &sk->addr;
}

inline struct sock **unix_sock_peer(struct unix_sock *sk) {
    return &sk->peer;
}

inline u16 *sockaddr_in_sin_port(struct sockaddr_in *sockaddr) {
    return &sockaddr->sin_port;
}

inline u32 *in_addr_s_addr(struct in_addr* addr) {
    return &addr->s_addr;
}

inline struct in_addr *sockaddr_in_sin_addr(struct sockaddr_in* sockaddr) {
    return &sockaddr->sin_addr;
}

inline u16 *sockaddr_in6_sin6_port(struct sockaddr_in6 *sockaddr) {
    return &sockaddr->sin6_port;
}

inline struct in6_addr *sockaddr_in6_sin6_addr(struct sockaddr_in6 *sockaddr) {
    return &sockaddr->sin6_addr;
}

inline unsigned char (*sockaddr_un_sun_path(struct sockaddr_un *sockaddr))[UNIX_PATH_MAX] {
    return &sockaddr->sun_path;
}

inline char **filename_name(struct filename *filename) {
    return &filename->name;
}

inline s32 *io_cqe_res(struct io_cqe *cqe) {
    return &cqe->res;
}

inline s32 *io_cqe_fd(struct io_cqe *cqe) {
    return &cqe->fd;
}

inline u16 *sockaddr_sa_family(struct sockaddr *sockaddr) {
    return &sockaddr->sa_family;
}

inline struct sockaddr *io_async_msghdr_addr(struct io_async_msghdr *io) {
    return &io->addr;
}

inline struct file **io_kiocb_file(struct io_kiocb *req) {
    return &req->file;
}

inline struct io_cmd_data *io_kiocb_cmd(struct io_kiocb *req) {
    return &req->cmd;
}

inline u64 *io_kiocb_flags(struct io_kiocb *req) {
    return &req->flags;
}

inline struct io_cqe *io_kiocb_cqe(struct io_kiocb *req) {
    return &req->cqe;
}

inline void **io_kiocb_async_data(struct io_kiocb *req) {
    return &req->async_data;
}

inline s32 *io_rename_old_dfd(struct io_rename *ren) {
    return &ren->old_dfd;
}

inline s32 *io_rename_new_dfd(struct io_rename *ren) {
    return &ren->new_dfd;
}

inline struct filename **io_rename_oldpath(struct io_rename *ren) {
    return &ren->oldpath;
}

inline struct filename **io_rename_newpath(struct io_rename *ren) {
    return &ren->newpath;
}

inline s32 *io_rename_flags(struct io_rename *ren) {
    return &ren->flags;
}

inline s32 *io_unlink_dfd(struct io_unlink *un) {
    return &un->dfd;
}

inline s32 *io_unlink_flags(struct io_unlink *un) {
    return &un->flags;
}

inline struct filename **io_unlink_filename(struct io_unlink *un) {
    return &un->filename;
}

inline s32 *io_socket_domain(struct io_socket *sock) {
    return &sock->domain;
}

inline s32 *io_socket_type(struct io_socket *sock) {
    return &sock->type;
}

inline s32 *io_socket_protocol(struct io_socket *sock) {
    return &sock->protocol;
}

inline s32 *io_socket_flags(struct io_socket *sock) {
    return &sock->flags;
}

inline u32 *io_socket_file_slot(struct io_socket *sock) {
    return &sock->file_slot;
}

inline s32 *io_bind_addr_len(struct io_bind *bind) {
	return &bind->addr_len;
}

#if defined(__bpf__)
#pragma clang attribute pop
#endif

#endif
