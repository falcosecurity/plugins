#ifndef __CORE_HELPERS_H__
#define __CORE_HELPERS_H__

#if defined(__bpf__)
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
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
struct sockaddr {};

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
    char sun_path[UNIX_PATH_MAX];
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

// FIXME(ekoops): the following doesn't work, as clang doesn't recognize `__builtin_preserve_type_info`
///* second argument to __builtin_preserve_type_info() built-in */
//enum bpf_type_info_kind {
//	BPF_TYPE_EXISTS = 0,		/* type existence in target kernel */
//	BPF_TYPE_SIZE = 1,		/* type size in target kernel */
//	BPF_TYPE_MATCHES = 2,		/* type match in target kernel */
//};
//#define ___bpf_typeof(type) ((typeof(type) *) 0)
//#define bpf_core_type_size(type) __builtin_preserve_type_info(*___bpf_typeof(type), BPF_TYPE_SIZE)
//
//inline struct dentry *inode_dentry_ptr(struct inode *inode) {
//    unsigned long inode_size = bpf_core_type_size(struct inode);
//    if(!inode_size) {
//        return 0;
//    }
//    return (struct dentry*) ((char *)inode + inode_size);
//}

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

inline char (*sockaddr_un_sun_path(struct sockaddr_un *sockaddr))[UNIX_PATH_MAX] {
    return &sockaddr->sun_path;
}

inline char **filename_name(struct filename *filename) {
    return &filename->name;
}

#if defined(__bpf__)
#pragma clang attribute pop
#endif

#endif
