# Falcosecurity `anomalydetection` Plugin

This `anomalydetection` plugin has been created upon this [Proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20230620-anomaly-detection-framework.md).

## Introduction

The `anomalydetection` plugin enhances {syscall} event analysis by incorporating anomaly detection estimates for probabilistic filtering.

### Functionality

The initial scope will focus exclusively on "CountMinSketch Powered Probabilistic Counting and Filtering" for a subset of syscalls and a selection of options to define behavior profiles. The primary objective of this new framework is to offer tangible advantages in real-world production environments and substantially improve the usability of standard Falco rules. Essentially, this framework eliminates the requirement for meticulous tuning of individual rules and facilitates the utilization of probabilistic count estimates to alleviate the impact of noisy rules. Additionally, it enables the creation of broader Falco rules. Read more in the [Proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20230620-anomaly-detection-framework.md).

### Plugin Official Name

`anomalydetection`

## Capabilities

The `anomalydetection` plugin implements 2 capabilities:

* `extraction`
* `parsing`

## Supported Fields

Here is the current set of supported fields:

<!-- README-PLUGIN-FIELDS -->
|       NAME        |   TYPE   |       ARG       |                               DESCRIPTION                               |
|-------------------|----------|-----------------|-------------------------------------------------------------------------|
| `anomaly.count_min_sketch` | `uint64` | Key, Optional | Count Min Sketch Estimate according to the specified behavior profile for a predefined set of {syscalls} events. Access different behavior profiles/sketches using indices. For instance, anomaly.count_min_sketch[0] retrieves the first behavior profile defined in the plugins' `init_config`. |
| `anomaly.count_min_sketch.profile` | `string` | Key, Optional | Concatenated string according to the specified behavior profile (not preserving original order). Access different behavior profiles using indices. For instance, anomaly.count_min_sketch.profile[0] retrieves the first behavior profile defined in the plugins' `init_config`. |
<!-- /README-PLUGIN-FIELDS -->

## Usage

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: anomalydetection
    library_path: libanomalydetection.so
    init_config:
      count_min_sketch:
        enabled: true
        n_sketches: 3
        # `gamma_eps`: auto-calculate rows and cols; usage: [[gamma, eps], ...];
        # gamma -> error probability -> determine d / rows / number of hash functions
        # eps -> relative error -> determine w / cols / number of buckets
        gamma_eps: [
          [0.001, 0.0001],
          [0.001, 0.0001],
          [0.001, 0.0001]
        ]
        # `rows_cols`: pass explicit dimensions, supersedes `gamma_eps`; usage: [[7, 27183], ...]; by default disabled when not used.
        # rows_cols: []
        behavior_profiles: [
          {
            "fields": "%container.id %proc.name %proc.aname[1] %proc.aname[2] %proc.aname[3] %proc.exepath %proc.tty %proc.vpgid.name %proc.sname",
            # execve, execveat
            "event_codes": [293, 331]
          },
          {
            "fields": "%container.id %proc.name %proc.aname[1] %proc.aname[2] %proc.aname[3] %proc.exepath %proc.tty %proc.vpgid.name %proc.sname %fd.name",
            # open, openat, openat2
            "event_codes": [3, 307, 327]
          },
          {
            "fields": "%container.id %proc.args",
            # execve, execveat
            "event_codes": [293, 331]
          }
        ]

load_plugins: [anomalydetection]
```

The first version is quite restrictive because the plugin API is not yet complete for this use case. Currently, you have to manually look up the correct PPME event codes. Always use the highest / latest event version, for example `PPME_SYSCALL_EXECVE_19_X` for the exit event of the `execve` syscall or `PPME_SYSCALL_OPENAT_2_X` for the `openat` syscall. Read this [blog post](https://falco.org/blog/adaptive-syscalls-selection/) to learn more about PPME event codes versus syscall names. See the [PPME event codes](#ppme-event-codes) reference below.

**Open Parameters**:

This plugin does not have open params.

**Rules**

This plugin does not provide any custom rules. You can use the default Falco ruleset and add the necessary `anomalydetection` fields as output fields to obtain the Count Min Sketch estimates and/or use them in the familiar rules filter condition.

Example of a standard Falco rule using the `anomalydetection` fields:

```yaml
- macro: spawned_process
  condition: (evt.type in (execve, execveat) and evt.dir=<)
- rule: execve count_min_sketch test
  desc: "execve count_min_sketch test"
  condition: spawned_process and proc.name=cat and anomaly.count_min_sketch > 10
  output: '%anomaly.count_min_sketch %proc.pid %proc.ppid %proc.name %user.loginuid %user.name %user.uid %proc.cmdline %container.id %evt.type %evt.res %proc.cwd %proc.sid %proc.exepath %container.image.repository'
  priority: NOTICE
  tags: [maturity_sandbox, host, container, process, anomalydetection]
```

__NOTE__: Ensure you regularly execute `cat` commands. Once you have done so frequently enough, logs will start to appear. Alternatively, perform an inverse test to observe how quickly a very noisy rule gets silenced.

### Running

This plugin requires Falco with version >= **0.37.0**.
Modify the `falco.yaml` with the provided [configuration](#configuration) above and you are ready to go!

```shell
sudo falco -c falco.yaml -r falco_rules.yaml
```

## Local Development

### Build

```bash
git clone https://github.com/falcosecurity/plugins.git
cd plugins/anomalydetection
rm -f libanomalydetection.so; 
rm -f build/libanomalydetection.so; 
make;
# Copy the shared library to the expected location for `falco.yaml`, which is `library_path: libanomalydetection.so`
sudo mkdir -p /usr/share/falco/plugins/;
sudo cp -f libanomalydetection.so /usr/share/falco/plugins/libanomalydetection.so;
```


## References

### PPME event codes

```
typedef enum {
	PPME_GENERIC_E = 0,
	PPME_GENERIC_X = 1,
	PPME_SYSCALL_OPEN_E = 2,
	PPME_SYSCALL_OPEN_X = 3,
	PPME_SYSCALL_CLOSE_E = 4,
	PPME_SYSCALL_CLOSE_X = 5,
	PPME_SYSCALL_READ_E = 6,
	PPME_SYSCALL_READ_X = 7,
	PPME_SYSCALL_WRITE_E = 8,
	PPME_SYSCALL_WRITE_X = 9,
	PPME_SYSCALL_BRK_1_E = 10,
	PPME_SYSCALL_BRK_1_X = 11,
	PPME_SYSCALL_EXECVE_8_E = 12,
	PPME_SYSCALL_EXECVE_8_X = 13,
	PPME_SYSCALL_CLONE_11_E = 14,
	PPME_SYSCALL_CLONE_11_X = 15,
	PPME_PROCEXIT_E = 16,
	PPME_PROCEXIT_X = 17,	/* This should never be called */
	PPME_SOCKET_SOCKET_E = 18,
	PPME_SOCKET_SOCKET_X = 19,
	PPME_SOCKET_BIND_E = 20,
	PPME_SOCKET_BIND_X = 21,
	PPME_SOCKET_CONNECT_E = 22,
	PPME_SOCKET_CONNECT_X = 23,
	PPME_SOCKET_LISTEN_E = 24,
	PPME_SOCKET_LISTEN_X = 25,
	PPME_SOCKET_ACCEPT_E = 26,
	PPME_SOCKET_ACCEPT_X = 27,
	PPME_SOCKET_SEND_E = 28,
	PPME_SOCKET_SEND_X = 29,
	PPME_SOCKET_SENDTO_E = 30,
	PPME_SOCKET_SENDTO_X = 31,
	PPME_SOCKET_RECV_E = 32,
	PPME_SOCKET_RECV_X = 33,
	PPME_SOCKET_RECVFROM_E = 34,
	PPME_SOCKET_RECVFROM_X = 35,
	PPME_SOCKET_SHUTDOWN_E = 36,
	PPME_SOCKET_SHUTDOWN_X = 37,
	PPME_SOCKET_GETSOCKNAME_E = 38,
	PPME_SOCKET_GETSOCKNAME_X = 39,
	PPME_SOCKET_GETPEERNAME_E = 40,
	PPME_SOCKET_GETPEERNAME_X = 41,
	PPME_SOCKET_SOCKETPAIR_E = 42,
	PPME_SOCKET_SOCKETPAIR_X = 43,
	PPME_SOCKET_SETSOCKOPT_E = 44,
	PPME_SOCKET_SETSOCKOPT_X = 45,
	PPME_SOCKET_GETSOCKOPT_E = 46,
	PPME_SOCKET_GETSOCKOPT_X = 47,
	PPME_SOCKET_SENDMSG_E = 48,
	PPME_SOCKET_SENDMSG_X = 49,
	PPME_SOCKET_SENDMMSG_E = 50,
	PPME_SOCKET_SENDMMSG_X = 51,
	PPME_SOCKET_RECVMSG_E = 52,
	PPME_SOCKET_RECVMSG_X = 53,
	PPME_SOCKET_RECVMMSG_E = 54,
	PPME_SOCKET_RECVMMSG_X = 55,
	PPME_SOCKET_ACCEPT4_E = 56,
	PPME_SOCKET_ACCEPT4_X = 57,
	PPME_SYSCALL_CREAT_E = 58,
	PPME_SYSCALL_CREAT_X = 59,
	PPME_SYSCALL_PIPE_E = 60,
	PPME_SYSCALL_PIPE_X = 61,
	PPME_SYSCALL_EVENTFD_E = 62,
	PPME_SYSCALL_EVENTFD_X = 63,
	PPME_SYSCALL_FUTEX_E = 64,
	PPME_SYSCALL_FUTEX_X = 65,
	PPME_SYSCALL_STAT_E = 66,
	PPME_SYSCALL_STAT_X = 67,
	PPME_SYSCALL_LSTAT_E = 68,
	PPME_SYSCALL_LSTAT_X = 69,
	PPME_SYSCALL_FSTAT_E = 70,
	PPME_SYSCALL_FSTAT_X = 71,
	PPME_SYSCALL_STAT64_E = 72,
	PPME_SYSCALL_STAT64_X = 73,
	PPME_SYSCALL_LSTAT64_E = 74,
	PPME_SYSCALL_LSTAT64_X = 75,
	PPME_SYSCALL_FSTAT64_E = 76,
	PPME_SYSCALL_FSTAT64_X = 77,
	PPME_SYSCALL_EPOLLWAIT_E = 78,
	PPME_SYSCALL_EPOLLWAIT_X = 79,
	PPME_SYSCALL_POLL_E = 80,
	PPME_SYSCALL_POLL_X = 81,
	PPME_SYSCALL_SELECT_E = 82,
	PPME_SYSCALL_SELECT_X = 83,
	PPME_SYSCALL_NEWSELECT_E = 84,
	PPME_SYSCALL_NEWSELECT_X = 85,
	PPME_SYSCALL_LSEEK_E = 86,
	PPME_SYSCALL_LSEEK_X = 87,
	PPME_SYSCALL_LLSEEK_E = 88,
	PPME_SYSCALL_LLSEEK_X = 89,
	PPME_SYSCALL_IOCTL_2_E = 90,
	PPME_SYSCALL_IOCTL_2_X = 91,
	PPME_SYSCALL_GETCWD_E = 92,
	PPME_SYSCALL_GETCWD_X = 93,
	PPME_SYSCALL_CHDIR_E = 94,
	PPME_SYSCALL_CHDIR_X = 95,
	PPME_SYSCALL_FCHDIR_E = 96,
	PPME_SYSCALL_FCHDIR_X = 97,
	/* mkdir/rmdir events are not emitted anymore */
	PPME_SYSCALL_MKDIR_E = 98,
	PPME_SYSCALL_MKDIR_X = 99,
	PPME_SYSCALL_RMDIR_E = 100,
	PPME_SYSCALL_RMDIR_X = 101,
	PPME_SYSCALL_OPENAT_E = 102,
	PPME_SYSCALL_OPENAT_X = 103,
	PPME_SYSCALL_LINK_E = 104,
	PPME_SYSCALL_LINK_X = 105,
	PPME_SYSCALL_LINKAT_E = 106,
	PPME_SYSCALL_LINKAT_X = 107,
	PPME_SYSCALL_UNLINK_E = 108,
	PPME_SYSCALL_UNLINK_X = 109,
	PPME_SYSCALL_UNLINKAT_E = 110,
	PPME_SYSCALL_UNLINKAT_X = 111,
	PPME_SYSCALL_PREAD_E = 112,
	PPME_SYSCALL_PREAD_X = 113,
	PPME_SYSCALL_PWRITE_E = 114,
	PPME_SYSCALL_PWRITE_X = 115,
	PPME_SYSCALL_READV_E = 116,
	PPME_SYSCALL_READV_X = 117,
	PPME_SYSCALL_WRITEV_E = 118,
	PPME_SYSCALL_WRITEV_X = 119,
	PPME_SYSCALL_PREADV_E = 120,
	PPME_SYSCALL_PREADV_X = 121,
	PPME_SYSCALL_PWRITEV_E = 122,
	PPME_SYSCALL_PWRITEV_X = 123,
	PPME_SYSCALL_DUP_E = 124,
	PPME_SYSCALL_DUP_X = 125,
	PPME_SYSCALL_SIGNALFD_E = 126,
	PPME_SYSCALL_SIGNALFD_X = 127,
	PPME_SYSCALL_KILL_E = 128,
	PPME_SYSCALL_KILL_X = 129,
	PPME_SYSCALL_TKILL_E = 130,
	PPME_SYSCALL_TKILL_X = 131,
	PPME_SYSCALL_TGKILL_E = 132,
	PPME_SYSCALL_TGKILL_X = 133,
	PPME_SYSCALL_NANOSLEEP_E = 134,
	PPME_SYSCALL_NANOSLEEP_X = 135,
	PPME_SYSCALL_TIMERFD_CREATE_E = 136,
	PPME_SYSCALL_TIMERFD_CREATE_X = 137,
	PPME_SYSCALL_INOTIFY_INIT_E = 138,
	PPME_SYSCALL_INOTIFY_INIT_X = 139,
	PPME_SYSCALL_GETRLIMIT_E = 140,
	PPME_SYSCALL_GETRLIMIT_X = 141,
	PPME_SYSCALL_SETRLIMIT_E = 142,
	PPME_SYSCALL_SETRLIMIT_X = 143,
	PPME_SYSCALL_PRLIMIT_E = 144,
	PPME_SYSCALL_PRLIMIT_X = 145,
	PPME_SCHEDSWITCH_1_E = 146,
	PPME_SCHEDSWITCH_1_X = 147,	/* This should never be called */
	PPME_DROP_E = 148,  /* For internal use */
	PPME_DROP_X = 149,	/* For internal use */
	PPME_SYSCALL_FCNTL_E = 150,  /* For internal use */
	PPME_SYSCALL_FCNTL_X = 151,	/* For internal use */
	PPME_SCHEDSWITCH_6_E = 152,
	PPME_SCHEDSWITCH_6_X = 153,	/* This should never be called */
	PPME_SYSCALL_EXECVE_13_E = 154,
	PPME_SYSCALL_EXECVE_13_X = 155,
	PPME_SYSCALL_CLONE_16_E = 156,
	PPME_SYSCALL_CLONE_16_X = 157,
	PPME_SYSCALL_BRK_4_E = 158,
	PPME_SYSCALL_BRK_4_X = 159,
	PPME_SYSCALL_MMAP_E = 160,
	PPME_SYSCALL_MMAP_X = 161,
	PPME_SYSCALL_MMAP2_E = 162,
	PPME_SYSCALL_MMAP2_X = 163,
	PPME_SYSCALL_MUNMAP_E = 164,
	PPME_SYSCALL_MUNMAP_X = 165,
	PPME_SYSCALL_SPLICE_E = 166,
	PPME_SYSCALL_SPLICE_X = 167,
	PPME_SYSCALL_PTRACE_E = 168,
	PPME_SYSCALL_PTRACE_X = 169,
	PPME_SYSCALL_IOCTL_3_E = 170,
	PPME_SYSCALL_IOCTL_3_X = 171,
	PPME_SYSCALL_EXECVE_14_E = 172,
	PPME_SYSCALL_EXECVE_14_X = 173,
	PPME_SYSCALL_RENAME_E = 174,
	PPME_SYSCALL_RENAME_X = 175,
	PPME_SYSCALL_RENAMEAT_E = 176,
	PPME_SYSCALL_RENAMEAT_X = 177,
	PPME_SYSCALL_SYMLINK_E = 178,
	PPME_SYSCALL_SYMLINK_X = 179,
	PPME_SYSCALL_SYMLINKAT_E = 180,
	PPME_SYSCALL_SYMLINKAT_X = 181,
	PPME_SYSCALL_FORK_E = 182,
	PPME_SYSCALL_FORK_X = 183,
	PPME_SYSCALL_VFORK_E = 184,
	PPME_SYSCALL_VFORK_X = 185,
	PPME_PROCEXIT_1_E = 186,
	PPME_PROCEXIT_1_X = 187,	/* This should never be called */
	PPME_SYSCALL_SENDFILE_E = 188,
	PPME_SYSCALL_SENDFILE_X = 189,	/* This should never be called */
	PPME_SYSCALL_QUOTACTL_E = 190,
	PPME_SYSCALL_QUOTACTL_X = 191,
	PPME_SYSCALL_SETRESUID_E = 192,
	PPME_SYSCALL_SETRESUID_X = 193,
	PPME_SYSCALL_SETRESGID_E = 194,
	PPME_SYSCALL_SETRESGID_X = 195,
	PPME_SCAPEVENT_E = 196,
	PPME_SCAPEVENT_X = 197, /* This should never be called */
	PPME_SYSCALL_SETUID_E = 198,
	PPME_SYSCALL_SETUID_X = 199,
	PPME_SYSCALL_SETGID_E = 200,
	PPME_SYSCALL_SETGID_X = 201,
	PPME_SYSCALL_GETUID_E = 202,
	PPME_SYSCALL_GETUID_X = 203,
	PPME_SYSCALL_GETEUID_E = 204,
	PPME_SYSCALL_GETEUID_X = 205,
	PPME_SYSCALL_GETGID_E = 206,
	PPME_SYSCALL_GETGID_X = 207,
	PPME_SYSCALL_GETEGID_E = 208,
	PPME_SYSCALL_GETEGID_X = 209,
	PPME_SYSCALL_GETRESUID_E = 210,
	PPME_SYSCALL_GETRESUID_X = 211,
	PPME_SYSCALL_GETRESGID_E = 212,
	PPME_SYSCALL_GETRESGID_X = 213,
	PPME_SYSCALL_EXECVE_15_E = 214,
	PPME_SYSCALL_EXECVE_15_X = 215,
	PPME_SYSCALL_CLONE_17_E = 216,
	PPME_SYSCALL_CLONE_17_X = 217,
	PPME_SYSCALL_FORK_17_E = 218,
	PPME_SYSCALL_FORK_17_X = 219,
	PPME_SYSCALL_VFORK_17_E = 220,
	PPME_SYSCALL_VFORK_17_X = 221,
	PPME_SYSCALL_CLONE_20_E = 222,
	PPME_SYSCALL_CLONE_20_X = 223,
	PPME_SYSCALL_FORK_20_E = 224,
	PPME_SYSCALL_FORK_20_X = 225,
	PPME_SYSCALL_VFORK_20_E = 226,
	PPME_SYSCALL_VFORK_20_X = 227,
	PPME_CONTAINER_E = 228,
	PPME_CONTAINER_X = 229,
	PPME_SYSCALL_EXECVE_16_E = 230,
	PPME_SYSCALL_EXECVE_16_X = 231,
	PPME_SIGNALDELIVER_E = 232,
	PPME_SIGNALDELIVER_X = 233, /* This should never be called */
	PPME_PROCINFO_E = 234,
	PPME_PROCINFO_X = 235,	/* This should never be called */
	PPME_SYSCALL_GETDENTS_E = 236,
	PPME_SYSCALL_GETDENTS_X = 237,
	PPME_SYSCALL_GETDENTS64_E = 238,
	PPME_SYSCALL_GETDENTS64_X = 239,
	PPME_SYSCALL_SETNS_E = 240,
	PPME_SYSCALL_SETNS_X = 241,
	PPME_SYSCALL_FLOCK_E = 242,
	PPME_SYSCALL_FLOCK_X = 243,
	PPME_CPU_HOTPLUG_E = 244,
	PPME_CPU_HOTPLUG_X = 245, /* This should never be called */
	PPME_SOCKET_ACCEPT_5_E = 246,
	PPME_SOCKET_ACCEPT_5_X = 247,
	PPME_SOCKET_ACCEPT4_5_E = 248,
	PPME_SOCKET_ACCEPT4_5_X = 249,
	PPME_SYSCALL_SEMOP_E = 250,
	PPME_SYSCALL_SEMOP_X = 251,
	PPME_SYSCALL_SEMCTL_E = 252,
	PPME_SYSCALL_SEMCTL_X = 253,
	PPME_SYSCALL_PPOLL_E = 254,
	PPME_SYSCALL_PPOLL_X = 255,
	PPME_SYSCALL_MOUNT_E = 256,
	PPME_SYSCALL_MOUNT_X = 257,
	PPME_SYSCALL_UMOUNT_E = 258,
	PPME_SYSCALL_UMOUNT_X = 259,
	PPME_K8S_E = 260,
	PPME_K8S_X = 261,
	PPME_SYSCALL_SEMGET_E = 262,
	PPME_SYSCALL_SEMGET_X = 263,
	PPME_SYSCALL_ACCESS_E = 264,
	PPME_SYSCALL_ACCESS_X = 265,
	PPME_SYSCALL_CHROOT_E = 266,
	PPME_SYSCALL_CHROOT_X = 267,
	PPME_TRACER_E = 268,
	PPME_TRACER_X = 269,
	PPME_MESOS_E = 270,
	PPME_MESOS_X = 271,
	PPME_CONTAINER_JSON_E = 272,
	PPME_CONTAINER_JSON_X = 273,
	PPME_SYSCALL_SETSID_E = 274,
	PPME_SYSCALL_SETSID_X = 275,
	PPME_SYSCALL_MKDIR_2_E = 276,
	PPME_SYSCALL_MKDIR_2_X = 277,
	PPME_SYSCALL_RMDIR_2_E = 278,
	PPME_SYSCALL_RMDIR_2_X = 279,
	PPME_NOTIFICATION_E = 280,
	PPME_NOTIFICATION_X = 281,
	PPME_SYSCALL_EXECVE_17_E = 282,
	PPME_SYSCALL_EXECVE_17_X = 283,
	PPME_SYSCALL_UNSHARE_E = 284,
	PPME_SYSCALL_UNSHARE_X = 285,
	PPME_INFRASTRUCTURE_EVENT_E = 286,
	PPME_INFRASTRUCTURE_EVENT_X = 287,
	PPME_SYSCALL_EXECVE_18_E = 288,
	PPME_SYSCALL_EXECVE_18_X = 289,
	PPME_PAGE_FAULT_E = 290,
	PPME_PAGE_FAULT_X = 291,
	PPME_SYSCALL_EXECVE_19_E = 292,
	PPME_SYSCALL_EXECVE_19_X = 293,
	PPME_SYSCALL_SETPGID_E = 294,
	PPME_SYSCALL_SETPGID_X = 295,
	PPME_SYSCALL_BPF_E = 296,
	PPME_SYSCALL_BPF_X = 297,
	PPME_SYSCALL_SECCOMP_E = 298,
	PPME_SYSCALL_SECCOMP_X = 299,
	PPME_SYSCALL_UNLINK_2_E = 300,
	PPME_SYSCALL_UNLINK_2_X = 301,
	PPME_SYSCALL_UNLINKAT_2_E = 302,
	PPME_SYSCALL_UNLINKAT_2_X = 303,
	PPME_SYSCALL_MKDIRAT_E = 304,
	PPME_SYSCALL_MKDIRAT_X = 305,
	PPME_SYSCALL_OPENAT_2_E = 306,
	PPME_SYSCALL_OPENAT_2_X = 307,
	PPME_SYSCALL_LINK_2_E = 308,
	PPME_SYSCALL_LINK_2_X = 309,
	PPME_SYSCALL_LINKAT_2_E = 310,
	PPME_SYSCALL_LINKAT_2_X = 311,
	PPME_SYSCALL_FCHMODAT_E = 312,
	PPME_SYSCALL_FCHMODAT_X = 313,
	PPME_SYSCALL_CHMOD_E = 314,
	PPME_SYSCALL_CHMOD_X = 315,
	PPME_SYSCALL_FCHMOD_E = 316,
	PPME_SYSCALL_FCHMOD_X = 317,
	PPME_SYSCALL_RENAMEAT2_E = 318,
	PPME_SYSCALL_RENAMEAT2_X = 319,
	PPME_SYSCALL_USERFAULTFD_E = 320,
	PPME_SYSCALL_USERFAULTFD_X = 321,
	PPME_PLUGINEVENT_E = 322,
	PPME_PLUGINEVENT_X = 323,
	PPME_CONTAINER_JSON_2_E = 324,
	PPME_CONTAINER_JSON_2_X = 325,
	PPME_SYSCALL_OPENAT2_E = 326,
	PPME_SYSCALL_OPENAT2_X = 327,
	PPME_SYSCALL_MPROTECT_E = 328,
	PPME_SYSCALL_MPROTECT_X = 329,
	PPME_SYSCALL_EXECVEAT_E = 330,
	PPME_SYSCALL_EXECVEAT_X = 331,
	PPME_SYSCALL_COPY_FILE_RANGE_E = 332,
	PPME_SYSCALL_COPY_FILE_RANGE_X = 333,
	PPME_SYSCALL_CLONE3_E = 334,
	PPME_SYSCALL_CLONE3_X = 335,
	PPME_SYSCALL_OPEN_BY_HANDLE_AT_E = 336,
	PPME_SYSCALL_OPEN_BY_HANDLE_AT_X = 337,
	PPME_SYSCALL_IO_URING_SETUP_E = 338,
	PPME_SYSCALL_IO_URING_SETUP_X = 339,
	PPME_SYSCALL_IO_URING_ENTER_E = 340,
	PPME_SYSCALL_IO_URING_ENTER_X = 341,
	PPME_SYSCALL_IO_URING_REGISTER_E = 342,
	PPME_SYSCALL_IO_URING_REGISTER_X = 343,
	PPME_SYSCALL_MLOCK_E = 344,
	PPME_SYSCALL_MLOCK_X = 345,
	PPME_SYSCALL_MUNLOCK_E = 346,
	PPME_SYSCALL_MUNLOCK_X = 347,
	PPME_SYSCALL_MLOCKALL_E = 348,
	PPME_SYSCALL_MLOCKALL_X = 349,
	PPME_SYSCALL_MUNLOCKALL_E = 350,
	PPME_SYSCALL_MUNLOCKALL_X = 351,
	PPME_SYSCALL_CAPSET_E = 352,
	PPME_SYSCALL_CAPSET_X = 353,
	PPME_USER_ADDED_E = 354,
	PPME_USER_ADDED_X = 355,
	PPME_USER_DELETED_E = 356,
	PPME_USER_DELETED_X = 357,
	PPME_GROUP_ADDED_E = 358,
	PPME_GROUP_ADDED_X = 359,
	PPME_GROUP_DELETED_E = 360,
	PPME_GROUP_DELETED_X = 361,
	PPME_SYSCALL_DUP2_E = 362,
	PPME_SYSCALL_DUP2_X = 363,
	PPME_SYSCALL_DUP3_E = 364,
	PPME_SYSCALL_DUP3_X = 365,
	PPME_SYSCALL_DUP_1_E = 366,
	PPME_SYSCALL_DUP_1_X = 367,
	PPME_SYSCALL_BPF_2_E = 368,
	PPME_SYSCALL_BPF_2_X = 369,
	PPME_SYSCALL_MLOCK2_E = 370,
	PPME_SYSCALL_MLOCK2_X = 371,
	PPME_SYSCALL_FSCONFIG_E = 372,
	PPME_SYSCALL_FSCONFIG_X = 373,
	PPME_SYSCALL_EPOLL_CREATE_E = 374,
	PPME_SYSCALL_EPOLL_CREATE_X = 375,
	PPME_SYSCALL_EPOLL_CREATE1_E = 376,
	PPME_SYSCALL_EPOLL_CREATE1_X = 377,
	PPME_SYSCALL_CHOWN_E = 378,
	PPME_SYSCALL_CHOWN_X = 379,
	PPME_SYSCALL_LCHOWN_E = 380,
	PPME_SYSCALL_LCHOWN_X = 381,
	PPME_SYSCALL_FCHOWN_E = 382,
	PPME_SYSCALL_FCHOWN_X = 383,
	PPME_SYSCALL_FCHOWNAT_E = 384,
	PPME_SYSCALL_FCHOWNAT_X = 385,
	PPME_SYSCALL_UMOUNT_1_E = 386,
	PPME_SYSCALL_UMOUNT_1_X = 387,
	PPME_SOCKET_ACCEPT4_6_E = 388,
	PPME_SOCKET_ACCEPT4_6_X = 389,
	PPME_SYSCALL_UMOUNT2_E = 390,
	PPME_SYSCALL_UMOUNT2_X = 391,
	PPME_SYSCALL_PIPE2_E = 392,
	PPME_SYSCALL_PIPE2_X = 393,
	PPME_SYSCALL_INOTIFY_INIT1_E = 394,
	PPME_SYSCALL_INOTIFY_INIT1_X = 395,
	PPME_SYSCALL_EVENTFD2_E = 396,
	PPME_SYSCALL_EVENTFD2_X = 397,
	PPME_SYSCALL_SIGNALFD4_E = 398,
	PPME_SYSCALL_SIGNALFD4_X = 399,
	PPME_SYSCALL_PRCTL_E = 400,
	PPME_SYSCALL_PRCTL_X = 401,
	PPME_ASYNCEVENT_E = 402,
	PPME_ASYNCEVENT_X = 403,
	PPME_SYSCALL_MEMFD_CREATE_E = 404,
	PPME_SYSCALL_MEMFD_CREATE_X = 405,
	PPME_SYSCALL_PIDFD_GETFD_E = 406,
	PPME_SYSCALL_PIDFD_GETFD_X = 407,
	PPME_SYSCALL_PIDFD_OPEN_E = 408,
	PPME_SYSCALL_PIDFD_OPEN_X = 409,
	PPME_SYSCALL_INIT_MODULE_E = 410,
	PPME_SYSCALL_INIT_MODULE_X = 411,
	PPME_SYSCALL_FINIT_MODULE_E = 412,
	PPME_SYSCALL_FINIT_MODULE_X = 413,
	PPME_SYSCALL_MKNOD_E = 414,
	PPME_SYSCALL_MKNOD_X = 415,
	PPME_SYSCALL_MKNODAT_E = 416,
	PPME_SYSCALL_MKNODAT_X = 417,
	PPME_SYSCALL_NEWFSTATAT_E = 418,
	PPME_SYSCALL_NEWFSTATAT_X = 419,
	PPME_SYSCALL_PROCESS_VM_READV_E = 420,
	PPME_SYSCALL_PROCESS_VM_READV_X = 421,
	PPME_SYSCALL_PROCESS_VM_WRITEV_E = 422,
	PPME_SYSCALL_PROCESS_VM_WRITEV_X = 423,
	PPME_SYSCALL_DELETE_MODULE_E = 424,
	PPME_SYSCALL_DELETE_MODULE_X = 425,
	PPM_EVENT_MAX = 426
} ppm_event_code;
```