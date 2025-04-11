#ifndef __CORE_HELPERS_H__
#define __CORE_HELPERS_H__

#if defined(__bpf__)
#pragma clang attribute push(__attribute__((preserve_access_index)), apply_to = record)
#endif

typedef long long unsigned int u64;
typedef unsigned int u32;
typedef int s32;

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

struct dentry {
	struct qstr d_name;
	struct inode *d_inode;
	struct super_block *d_sb;
};

struct path {
	struct dentry *dentry;
};

// Taken from 6.13.
struct file {
    u32 f_mode;
    u32 f_flags;
    struct inode *f_inode;
    struct path f_path;
};

inline u32 *file_f_mode(struct file *file) {
	return &file->f_mode;
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

#if defined(__bpf__)
#pragma clang attribute pop
#endif

#endif
