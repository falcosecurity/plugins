// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2024 The Falco Authors.

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

#include <falcosecurity/sdk.h>
#include "plugin_utils.h"

static const filtercheck_field_info sinsp_filter_check_fields[] =
{
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.exe", "First Argument", "The first command-line argument (i.e., argv[0]), typically the executable name or a custom string as specified by the user. It is primarily obtained from syscall arguments, truncated after 4096 bytes, or, as a fallback, by reading /proc/PID/cmdline, in which case it may be truncated after 1024 bytes. This field may differ from the last component of proc.exepath, reflecting how command invocation and execution paths can vary."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.pexe", "Parent First Argument", "The proc.exe (first command line argument argv[0]) of the parent process."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_ARG_ALLOWED | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "proc.aexe", "Ancestor First Argument", "The proc.exe (first command line argument argv[0]) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aexe[1] retrieves the proc.exe of the parent process, proc.aexe[2] retrieves the proc.exe of the grandparent process, and so on. The current process's proc.exe line can be obtained using proc.aexe[0]. When used without any arguments, proc.aexe is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aexe endswith java` to match any process ancestor whose proc.exe ends with the term `java`."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.exepath", "Process Executable Path", "The full executable path of a process, resolving to the canonical path for symlinks. This is primarily obtained from the kernel, or as a fallback, by reading /proc/PID/exe (in the latter case, the path is truncated after 1024 bytes). For eBPF drivers, due to verifier limits, path components may be truncated to 24 for legacy eBPF on kernel <5.2, 48 for legacy eBPF on kernel >=5.2, or 96 for modern eBPF."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.pexepath", "Parent Process Executable Path", "The proc.exepath (full executable path) of the parent process."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_ARG_ALLOWED | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "proc.aexepath", "Ancestor Executable Path", "The proc.exepath (full executable path) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aexepath[1] retrieves the proc.exepath of the parent process, proc.aexepath[2] retrieves the proc.exepath of the grandparent process, and so on. The current process's proc.exepath line can be obtained using proc.aexepath[0]. When used without any arguments, proc.aexepath is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aexepath endswith java` to match any process ancestor whose path ends with the term `java`."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.name", "Name", "The process name (truncated after 16 characters) generating the event (task->comm). Truncation is determined by kernel settings and not by Falco. This field is collected from the syscalls args or, as a fallback, extracted from /proc/PID/status. The name of the process and the name of the executable file on disk (if applicable) can be different if a process is given a custom name which is often the case for example for java applications."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.pname", "Parent Name", "The proc.name truncated after 16 characters) of the process generating the event."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_ARG_ALLOWED | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "proc.aname", "Ancestor Name", "The proc.name (truncated after 16 characters) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aname[1] retrieves the proc.name of the parent process, proc.aname[2] retrieves the proc.name of the grandparent process, and so on. The current process's proc.name line can be obtained using proc.aname[0]. When used without any arguments, proc.aname is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aname=bash` to match any process ancestor whose name is `bash`."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.args", "Arguments", "The arguments passed on the command line when starting the process generating the event excluding argv[0] (truncated after 4096 bytes). This field is collected from the syscalls args or, as a fallback, extracted from /proc/PID/cmdline."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.cmdline", "Command Line", "The concatenation of `proc.name + proc.args` (truncated after 4096 bytes) when starting the process generating the event."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.pcmdline", "Parent Command Line", "The proc.cmdline (full command line (proc.name + proc.args)) of the parent of the process generating the event."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_ARG_ALLOWED | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "proc.acmdline", "Ancestor Command Line", "The full command line (proc.name + proc.args) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.acmdline[1] retrieves the full command line of the parent process, proc.acmdline[2] retrieves the proc.cmdline of the grandparent process, and so on. The current process's full command line can be obtained using proc.acmdline[0]. When used without any arguments, proc.acmdline is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.acmdline contains base64` to match any process ancestor whose command line contains the term base64."},
	{PT_UINT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "proc.cmdnargs", "Number of Command Line args", "The number of command line args (proc.args)."},
	{PT_UINT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "proc.cmdlenargs", "Total Count of Characters in Command Line args", "The total count of characters / length of the command line args (proc.args) combined excluding whitespaces between args."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.exeline", "Executable Command Line", "The full command line, with exe as first argument (proc.exe + proc.args) when starting the process generating the event."},
	{PT_CHARBUF, EPF_ARG_ALLOWED, PF_NA, "proc.env", "Environment", "The environment variables of the process generating the event as concatenated string 'ENV_NAME=value ENV_NAME1=value1'. Can also be used to extract the value of a known env variable, e.g. proc.env[ENV_NAME]."},
	{PT_CHARBUF, EPF_ARG_ALLOWED | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "proc.aenv", "Ancestor Environment", "[EXPERIMENTAL] This field can be used in three flavors: (1) as a filter checking all parents, e.g. 'proc.aenv contains xyz', which is similar to the familiar 'proc.aname contains xyz' approach, (2) checking the `proc.env` of a specified level of the parent, e.g. 'proc.aenv[2]', which is similar to the familiar 'proc.aname[2]' approach, or (3) checking the first matched value of a known ENV_NAME in the parent lineage, such as 'proc.aenv[ENV_NAME]' (across a max of 20 ancestor levels). This field may be deprecated or undergo breaking changes in future releases. Please use it with caution."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.cwd", "Current Working Directory", "The current working directory of the event."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "proc.loginshellid", "Login Shell ID", "The pid of the oldest shell among the ancestors of the current process, if there is one. This field can be used to separate different user sessions."},
	{PT_UINT32, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "proc.tty", "Process TTY", "The controlling terminal of the process. 0 for processes without a terminal."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "proc.pid", "Process ID", "The id of the process generating the event."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "proc.ppid", "Parent Process ID", "The pid of the parent of the process generating the event."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_ARG_ALLOWED | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_ID, "proc.apid", "Ancestor Process ID", "The pid for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.apid[1] retrieves the pid of the parent process, proc.apid[2] retrieves the pid of the grandparent process, and so on. The current process's pid can be obtained using proc.apid[0]. When used without any arguments, proc.apid is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.apid=1337` to match any process ancestor whose pid is equal to 1337."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "proc.vpid", "Virtual Process ID", "The id of the process generating the event as seen from its current PID namespace."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "proc.pvpid", "Parent Virtual Process ID", "The id of the parent process generating the event as seen from its current PID namespace."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "proc.sid", "Process Session ID", "The session id of the process generating the event."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.sname", "Process Session Name", "The name of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.sid.exe", "Process Session First Argument", "The first command line argument argv[0] (usually the executable name or a custom one) of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.sid.exepath", "Process Session Executable Path", "The full executable path of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "proc.vpgid", "Process Virtual Group ID", "The process group id of the process generating the event, as seen from its current PID namespace."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.vpgid.name", "Process Group Name", "The name of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.vpgid.exe", "Process Group First Argument", "The first command line argument argv[0] (usually the executable name or a custom one) of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.vpgid.exepath", "Process Group Executable Path", "The full executable path of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.duration", "Process Duration", "Number of nanoseconds since the process started."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.ppid.duration", "Parent Process Duration", "Number of nanoseconds since the parent process started."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.pid.ts", "Process start ts", "Start of process as epoch timestamp in nanoseconds."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.ppid.ts", "Parent Process start ts", "Start of parent process as epoch timestamp in nanoseconds."},
	{PT_BOOL, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.is_exe_writable", "Process Executable Is Writable", "'true' if this process' executable file is writable by the same user that spawned the process."},
	{PT_BOOL, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.is_exe_upper_layer", "Process Executable Is In Upper Layer", "'true' if this process' executable file is in upper layer in overlayfs. This field value can only be trusted if the underlying kernel version is greater or equal than 3.18.0, since overlayfs was introduced at that time."},
	{PT_BOOL, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.is_exe_from_memfd", "Process Executable Is Stored In Memfd", "'true' if the executable file of the current process is an anonymous file created using memfd_create() and is being executed by referencing its file descriptor (fd). This type of file exists only in memory and not on disk. Relevant to detect malicious in-memory code injection. Requires kernel version greater or equal to 3.17.0."},
	{PT_BOOL, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.is_sid_leader", "Process Is Process Session Leader", "'true' if this process is the leader of the process session, proc.sid == proc.vpid. For host processes vpid reflects pid."},
	{PT_BOOL, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "proc.is_vpgid_leader", "Process Is Virtual Process Group Leader", "'true' if this process is the leader of the virtual process group, proc.vpgid == proc.vpid. For host processes vpgid and vpid reflect pgid and pid. Can help to distinguish if the process was 'directly' executed for instance in a tty (similar to bash history logging, `is_vpgid_leader` would be 'true') or executed as descendent process in the same process group which for example is the case when subprocesses are spawned from a script (`is_vpgid_leader` would be 'false')."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "proc.exe_ino", "Inode number of executable file on disk", "The inode number of the executable file on disk. Can be correlated with fd.ino."},
	{PT_ABSTIME, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "proc.exe_ino.ctime", "Last status change time (ctime) of executable file", "Last status change time of executable file (inode->ctime) as epoch timestamp in nanoseconds. Time is changed by writing or by setting inode information e.g. owner, group, link count, mode etc."},
	{PT_ABSTIME, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "proc.exe_ino.mtime", "Last modification time (mtime) of executable file", "Last modification time of executable file (inode->mtime) as epoch timestamp in nanoseconds. Time is changed by file modifications, e.g. by mknod, truncate, utime, write of more than zero bytes etc. For tracking changes in owner, group, link count or mode, use proc.exe_ino.ctime instead."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "proc.exe_ino.ctime_duration_proc_start", "Number of nanoseconds between ctime exe file and proc clone ts", "Number of nanoseconds between modifying status of executable image and spawning a new process using the changed executable image."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "proc.exe_ino.ctime_duration_pidns_start", "Number of nanoseconds between pidns start ts and ctime exe file", "Number of nanoseconds between PID namespace start ts and ctime exe file if PID namespace start predates ctime."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.pidns_init_start_ts", "Start ts of pid namespace", "Start of PID namespace (container or non container pid namespace) as epoch timestamp in nanoseconds."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "thread.cap_permitted", "Permitted capabilities", "The permitted capabilities set"},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "thread.cap_inheritable", "Inheritable capabilities", "The inheritable capabilities set"},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "thread.cap_effective", "Effective capabilities", "The effective capabilities set"},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_healthcheck", "Process Is Container Healthcheck", "'true' if this process is running as a part of the container's health check."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_liveness_probe", "Process Is Container Liveness", "'true' if this process is running as a part of the container's liveness probe."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_readiness_probe", "Process Is Container Readiness", "'true' if this process is running as a part of the container's readiness probe."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.fdopencount", "FD Count", "Number of open FDs for the process"},
	{PT_INT64, EPF_NONE, PF_DEC, "proc.fdlimit", "FD Limit", "Maximum number of FDs the process can open."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "proc.fdusage", "FD Usage", "The ratio between open FDs and maximum available FDs for the process."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmsize", "VM Size", "Total virtual memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmrss", "VM RSS", "Resident non-swapped memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmswap", "VM Swap", "Swapped memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.pfmajor", "Major Page Faults", "Number of major page faults since thread start."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.pfminor", "Minor Page Faults", "Number of minor page faults since thread start."},
	{PT_INT64, EPF_NONE, PF_ID, "thread.tid", "Thread ID", "The id of the thread generating the event."},
	{PT_BOOL, EPF_NONE, PF_NA, "thread.ismain", "Main Thread", "'true' if the thread generating the event is the main one in the process."},
	{PT_INT64, EPF_NONE, PF_ID, "thread.vtid", "Virtual Thread ID", "The id of the thread generating the event as seen from its current PID namespace."},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "thread.nametid", "Thread Name + ID", "This field chains the process name and tid of a thread and can be used as a specific identifier of a thread for a specific execve."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "thread.exectime", "Scheduled Thread CPU Time", "CPU time spent by the last scheduled thread, in nanoseconds. Exported by switch events only."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "thread.totexectime", "Current Thread CPU Time", "Total CPU time, in nanoseconds since the beginning of the capture, for the current thread. Exported by switch events only."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "thread.cgroups", "Thread Cgroups", "All cgroups the thread belongs to, aggregated into a single string."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "thread.cgroup", "Thread Cgroup", "The cgroup the thread belongs to, for a specific subsystem. e.g. thread.cgroup.cpuacct."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.nthreads", "Threads", "The number of alive threads that the process generating the event currently has, including the leader thread. Please note that the leader thread may not be here, in that case 'proc.nthreads' and 'proc.nchilds' are equal"},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.nchilds", "Children", "The number of alive not leader threads that the process generating the event currently has. This excludes the leader thread."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu", "Thread CPU", "The CPU consumed by the thread in the last second."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu.user", "Thread User CPU", "The user CPU consumed by the thread in the last second."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu.system", "Thread System CPU", "The system CPU consumed by the thread in the last second."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.vmsize", "Thread VM Size (kb)", "For the process main thread, this is the total virtual memory for the process (as kb). For the other threads, this field is zero."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.vmrss", "Thread VM RSS (kb)", "For the process main thread, this is the resident non-swapped memory for the process (as kb). For the other threads, this field is zero."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "thread.vmsize.b", "Thread VM Size (b)", "For the process main thread, this is the total virtual memory for the process (in bytes). For the other threads, this field is zero."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "thread.vmrss.b", "Thread VM RSS (b)", "For the process main thread, this is the resident non-swapped memory for the process (in bytes). For the other threads, this field is zero."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "container.id", "Container ID", "The truncated container ID (first 12 characters), e.g. 3ad7b26ded6d is extracted from the Linux cgroups by Falco within the kernel. Consequently, this field is reliably available and serves as the lookup key for Falco's synchronous or asynchronous requests against the container runtime socket to retrieve all other 'container.*' information. One important aspect to be aware of is that if the process occurs on the host, meaning not in the container PID namespace, this field is set to a string called 'host'. In Kubernetes, pod sandbox container processes can exist where `container.id` matches `k8s.pod.sandbox_id`, lacking other 'container.*' details."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.full_id", "Container ID", "The full container ID, e.g. 3ad7b26ded6d8e7b23da7d48fe889434573036c27ae5a74837233de441c3601e. In contrast to `container.id`, we enrich this field as part of the container engine enrichment. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.name", "Container Name", "The container name. In instances of userspace container engine lookup delays, this field may not be available yet. One important aspect to be aware of is that if the process occurs on the host, meaning not in the container PID namespace, this field is set to a string called 'host'."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image", "Image Name", "The container image name (e.g. falcosecurity/falco:latest for docker). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.id", "Image ID", "The container image id (e.g. 6f7e2741b66b). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.type", "Type", "The container type, e.g. docker, cri-o, containerd etc."},
	{PT_BOOL, EPF_NONE, PF_NA, "container.privileged", "Privileged", "'true' for containers running as privileged, 'false' otherwise. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.mounts", "Mounts", "A space-separated list of mount information. Each item in the list has the format 'source:dest:mode:rdrw:propagation'. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount", "Mount", "Information about a single mount, specified by number (e.g. container.mount[0]) or mount source (container.mount[/usr/local]). The pathname can be a glob (container.mount[/usr/local/*]), in which case the first matching mount will be returned. The information has the format 'source:dest:mode:rdrw:propagation'. If there is no mount with the specified index or matching the provided source, returns the string \"none\" instead of a NULL value. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.source", "Mount Source", "The mount source, specified by number (e.g. container.mount.source[0]) or mount destination (container.mount.source[/host/lib/modules]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.dest", "Mount Destination", "The mount destination, specified by number (e.g. container.mount.dest[0]) or mount source (container.mount.dest[/lib/modules]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.mode", "Mount Mode", "The mount mode, specified by number (e.g. container.mount.mode[0]) or mount source (container.mount.mode[/usr/local]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.rdwr", "Mount Read/Write", "The mount rdwr value, specified by number (e.g. container.mount.rdwr[0]) or mount source (container.mount.rdwr[/usr/local]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_ARG_REQUIRED, PF_NA, "container.mount.propagation", "Mount Propagation", "The mount propagation value, specified by number (e.g. container.mount.propagation[0]) or mount source (container.mount.propagation[/usr/local]). The pathname can be a glob. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.repository", "Repository", "The container image repository (e.g. falcosecurity/falco). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.tag", "Image Tag", "The container image tag (e.g. stable, latest). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.digest", "Registry Digest", "The container image registry digest (e.g. sha256:d977378f890d445c15e51795296e4e5062f109ce6da83e0a355fc4ad8699d27). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.healthcheck", "Health Check", "The container's health check. Will be the null value (\"N/A\") if no healthcheck configured, \"NONE\" if configured but explicitly not created, and the healthcheck command line otherwise. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.liveness_probe", "Liveness", "The container's liveness probe. Will be the null value (\"N/A\") if no liveness probe configured, the liveness probe command line otherwise. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.readiness_probe", "Readiness", "The container's readiness probe. Will be the null value (\"N/A\") if no readiness probe configured, the readiness probe command line otherwise. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_UINT64, EPF_NONE, PF_DEC, "container.start_ts", "Container start", "Container start as epoch timestamp in nanoseconds based on proc.pidns_init_start_ts and extracted in the kernel and not from the container runtime socket / container engine."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "container.duration", "Number of nanoseconds since container.start_ts", "Number of nanoseconds since container.start_ts."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.ip", "Container ip address", "The container's / pod's primary ip address as retrieved from the container engine. Only ipv4 addresses are tracked. Consider container.cni.json (CRI use case) for logging ip addresses for each network interface. In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.cni.json", "Container's / pod's CNI result json", "The container's / pod's CNI result field from the respective pod status info. It contains ip addresses for each network interface exposed as unparsed escaped JSON string. Supported for CRI container engine (containerd, cri-o runtimes), optimized for containerd (some non-critical JSON keys removed). Useful for tracking ips (ipv4 and ipv6, dual-stack support) for each network interface (multi-interface support). In instances of userspace container engine lookup delays, this field may not be available yet."},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_ID, "fd.num", "FD Number", "the unique number identifying the file descriptor."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "fd.type", "FD Type", "type of FD. Can be 'file', 'directory', 'ipv4', 'ipv6', 'unix', 'pipe', 'event', 'signalfd', 'eventpoll', 'inotify'  'signalfd' or 'memfd'."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "fd.typechar", "FD Type Char", "type of FD as a single character. Can be 'f' for file, 4 for IPv4 socket, 6 for IPv6 socket, 'u' for unix socket, p for pipe, 'e' for eventfd, 's' for signalfd, 'l' for eventpoll, 'i' for inotify, 'b' for bpf, 'u' for userfaultd, 'r' for io_uring, 'm' for memfd ,'o' for unknown."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.name", "FD Name", "FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.directory", "FD Directory", "If the fd is a file, the directory that contains it."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.filename", "FD Filename", "If the fd is a file, the filename without the path."},
	{PT_IPADDR, EPF_ANOMALY_PLUGIN | EPF_FILTER_ONLY | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.ip", "FD IP Address", "matches the ip address (client or server) of the fd."},
	{PT_IPADDR, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.cip", "FD Client Address", "client IP address."},
	{PT_IPADDR, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.sip", "FD Server Address", "server IP address."},
	{PT_IPADDR, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.lip", "FD Local Address", "local IP address."},
	{PT_IPADDR, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.rip", "FD Remote Address", "remote IP address."},
	{PT_PORT, EPF_ANOMALY_PLUGIN | EPF_FILTER_ONLY | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_DEC, "fd.port", "FD Port", "matches the port (either client or server) of the fd."},
	{PT_PORT, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "fd.cport", "FD Client Port", "for TCP/UDP FDs, the client port."},
	{PT_PORT, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "fd.sport", "FD Server Port", "for TCP/UDP FDs, server port."},
	{PT_PORT, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "fd.lport", "FD Local Port", "for TCP/UDP FDs, the local port."},
	{PT_PORT, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "fd.rport", "FD Remote Port", "for TCP/UDP FDs, the remote port."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.l4proto", "FD IP Protocol", "the IP protocol of a socket. Can be 'tcp', 'udp', 'icmp' or 'raw'."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.sockfamily", "FD Socket Family", "the socket family for socket events. Can be 'ip' or 'unix'."},
	{PT_BOOL, EPF_NONE, PF_NA, "fd.is_server", "FD Server", "'true' if the process owning this FD is the server endpoint in the connection."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.uid", "FD ID", "a unique identifier for the FD, created by chaining the FD number and the thread ID."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.containername", "FD Container Name", "chaining of the container ID and the FD name. Useful when trying to identify which container an FD belongs to."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "fd.containerdirectory", "FD Container Directory", "chaining of the container ID and the directory name. Useful when trying to identify which container a directory belongs to."},
	{PT_PORT, EPF_FILTER_ONLY | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.proto", "FD Protocol", "matches the protocol (either client or server) of the fd."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.cproto", "FD Client Protocol", "for TCP/UDP FDs, the client protocol."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.sproto", "FD Server Protocol", "for TCP/UDP FDs, server protocol."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.lproto", "FD Local Protocol", "for TCP/UDP FDs, the local protocol."},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.rproto", "FD Remote Protocol", "for TCP/UDP FDs, the remote protocol."},
	{PT_IPNET, EPF_ANOMALY_PLUGIN | EPF_FILTER_ONLY | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.net", "FD IP Network", "matches the IP network (client or server) of the fd."},
	{PT_IPNET, EPF_ANOMALY_PLUGIN | EPF_FILTER_ONLY | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.cnet", "FD Client Network", "matches the client IP network of the fd."},
	{PT_IPNET, EPF_ANOMALY_PLUGIN | EPF_FILTER_ONLY | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.snet", "FD Server Network", "matches the server IP network of the fd."},
	{PT_IPNET, EPF_ANOMALY_PLUGIN | EPF_FILTER_ONLY | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.lnet", "FD Local Network", "matches the local IP network of the fd."},
	{PT_IPNET, EPF_ANOMALY_PLUGIN | EPF_FILTER_ONLY | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.rnet", "FD Remote Network", "matches the remote IP network of the fd."},
	{PT_BOOL, EPF_NONE, PF_NA, "fd.connected", "FD Connected", "for TCP/UDP FDs, 'true' if the socket is connected."},
	{PT_BOOL, EPF_NONE, PF_NA, "fd.name_changed", "FD Name Changed", "True when an event changes the name of an fd used by this event. This can occur in some cases such as udp connections where the connection tuple changes."},
	{PT_CHARBUF, EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.cip.name", "FD Client Domain Name", "Domain name associated with the client IP address."},
	{PT_CHARBUF, EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.sip.name", "FD Server Domain Name", "Domain name associated with the server IP address."},
	{PT_CHARBUF, EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.lip.name", "FD Local Domain Name", "Domain name associated with the local IP address."},
	{PT_CHARBUF, EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_NA, "fd.rip.name", "FD Remote Domain Name", "Domain name associated with the remote IP address."},
	{PT_INT32, EPF_NONE, PF_HEX, "fd.dev", "FD Device", "device number (major/minor) containing the referenced file"},
	{PT_INT32, EPF_NONE, PF_DEC, "fd.dev.major", "FD Major Device", "major device number containing the referenced file"},
	{PT_INT32, EPF_NONE, PF_DEC, "fd.dev.minor", "FD Minor Device", "minor device number containing the referenced file"},
	{PT_INT64, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_DEC, "fd.ino", "FD Inode Number", "inode number of the referenced file"},
	{PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fd.nameraw", "FD Name Raw", "FD full name raw. Just like fd.name, but only used if fd is a file path. File path is kept raw with limited sanitization and without deriving the absolute path."},
	{PT_CHARBUF, EPF_IS_LIST | EPF_ARG_ALLOWED | EPF_NO_RHS | EPF_NO_TRANSFORMER, PF_DEC, "fd.types", "FD Type", "List of FD types in used. Can be passed an fd number e.g. fd.types[0] to get the type of stdout as a single item list."},
    {PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fs.path.name", "Path for Filesystem-related operation", "For any event type that deals with a filesystem path, the path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed."},
    {PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fs.path.nameraw", "Raw path for Filesystem-related operation", "For any event type that deals with a filesystem path, the path the file syscall is operating on. This path is always the path provided to the syscall and may not be fully resolved."},
    {PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fs.path.source", "Source path for Filesystem-related operation", "For any event type that deals with a filesystem path, and specifically for a source and target like mv, cp, etc, the source path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed."},
    {PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fs.path.sourceraw", "Source path for Filesystem-related operation", "For any event type that deals with a filesystem path, and specifically for a source and target like mv, cp, etc, the source path the file syscall is operating on. This path is always the path provided to the syscall and may not be fully resolved."},
    {PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fs.path.target", "Target path for Filesystem-related operation", "For any event type that deals with a filesystem path, and specifically for a target and target like mv, cp, etc, the target path the file syscall is operating on. This path is always fully resolved, prepending the thread cwd when needed."},
    {PT_CHARBUF, EPF_ANOMALY_PLUGIN | EPF_NONE, PF_NA, "fs.path.targetraw", "Target path for Filesystem-related operation", "For any event type that deals with a filesystem path, and specifically for a target and target like mv, cp, etc, the target path the file syscall is operating on. This path is always the path provided to the syscall and may not be fully resolved."},
};

// Temporary workaround; not as robust as libsinsp/eventformatter; 
// ideally the plugin API exposes more libsinsp functionality in the near-term
//
// No need for performance optimization atm as the typical use case is to have 
// less than 3-8 sketches
namespace plugin_anomalydetection::utils
{
const std::vector<plugin_sinsp_filterchecks_field> get_profile_fields(const std::string& behavior_profile)
{
    std::vector<plugin_sinsp_filterchecks_field> fields;
    std::regex pattern(R"(%(\S+))");
    std::sregex_iterator iter(behavior_profile.begin(), behavior_profile.end(), pattern);
    std::sregex_iterator end;

    plugin_sinsp_filterchecks::check_type id;
    std::string fieldname;
    std::int32_t argid = 0;
    std::string argname = "";

    while (iter != end)
    {
        auto rawfield = iter->str().substr(1);
        std::string fieldname = rawfield;
        for (size_t i = 0; i < sizeof(sinsp_filter_check_fields) / sizeof(sinsp_filter_check_fields[0]); ++i)
        {
            id = static_cast<plugin_sinsp_filterchecks::check_type>(i);
            if(id == plugin_sinsp_filterchecks::TYPE_APID ||
                id == plugin_sinsp_filterchecks::TYPE_ANAME ||
                id == plugin_sinsp_filterchecks::TYPE_AEXE ||
                id == plugin_sinsp_filterchecks::TYPE_AEXEPATH ||
                id == plugin_sinsp_filterchecks::TYPE_ACMDLINE)
            {
                size_t start_pos = rawfield.find('[');
                size_t end_pos = rawfield.find(']');
                if (start_pos != std::string::npos && end_pos != std::string::npos)
                {
                    fieldname = rawfield.substr(0, start_pos);
                    argid = std::stoi(rawfield.substr(start_pos + 1, end_pos - start_pos - 1));
                }
            }
            if ((sinsp_filter_check_fields[i].m_flags & EPF_ANOMALY_PLUGIN) && std::string(sinsp_filter_check_fields[i].m_name) == fieldname)
            {
                fields.emplace_back(plugin_sinsp_filterchecks_field{
                    id,
                    argid,
                    argname
                });
            }
            argid = 0;
            argname.clear();
        }
        ++iter;
    }
    return fields;
}
}
