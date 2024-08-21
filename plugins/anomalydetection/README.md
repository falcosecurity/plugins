# Falcosecurity `anomalydetection` Plugin

This `anomalydetection` plugin has been created upon this [Proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20230620-anomaly-detection-framework.md).

## Introduction

The `anomalydetection` plugin enhances {syscall} event analysis by incorporating anomaly detection estimates for probabilistic filtering.

### Functionality

The initial scope focuses exclusively on "CountMinSketch Powered Probabilistic Counting and Filtering" for a subset of syscalls and a selection of options for defining behavior profiles. This limitation is due to current restrictions related to the plugin API and SDK layout.

The new framework primarily aims to improve the usability of standard Falco rules. It may reduce the need for precise rule tuning, leverages probabilistic count estimates to auto-tune noisy rules on the fly, and enables the creation of broader Falco rules. Read more in the [Proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20230620-anomaly-detection-framework.md).

### TL;DR

The official documentation will eventually be available on the Falco [Plugins](https://falco.org/docs/plugins/) site. Therefore, consider this README as not being a complete documentation for using this plugin.

*Disclaimer*: Anomaly detection can mean different things to different people. It's best to keep your expectations low for this plugin's current capabilities. For now, it is focused solely on probabilistic counting.

What this plugin is:
- **Initial step for real-time anomaly detection in Falco**: Introduces basic real-time anomaly detection methods on the host.
- **Probabilistic counting**: Currently supports only probabilistic counting, with the guarantee that any overcounting remains within an acceptable error margin.
- **Use-case dependent**: Requires careful derivation of custom use cases; no default use cases are provided at this time.
- **Limited by current API**: Subject to several restrictions due to plugin API and other limitations.
- **Built for future extensibility**: Designed to support more algorithms in the future, limited to those that can be implemented in a single data pass to ensure real-time performance.
- **Documentation is insufficient**: Expect to need hands-on exploration to understand usage and restrictions.

What this plugin is not:
- **Not a pre-trained AI/ML model**.
- **Not ready out-of-the-box**: No default configuration or use cases are provided at this time.
- **Not a universal solution**: Does not offer a one-size-fits-all approach to anomaly detection.
- **No multi-pass algorithms**: Algorithms requiring multiple data passes are not planned; the plugin is intended to remain real-time and efficient for applicable use cases.
- **Not yet battle-tested in production**.

### Outlook

In the near term, the plan is to expand the syscalls for which behavior profiles can be applied and to enhance the fields available for defining these profiles. The first version is quite restrictive in this regard due to current plugin API limitations. Additionally, from an algorithmic and capabilities point of view, we will explore the following:

- Support for HyperLogLog probabilistic distinct counting (ETA unknown).
- Overcoming the cold start problem by loading sketch data structures and counts from previous agent runs or from test environments (ETA unknown).
- Efficient and feasible options for real-time, single-pass time series analysis (ETA unknown).

### Plugin Official Name

`anomalydetection`

## Capabilities

The `anomalydetection` plugin implements 2 capabilities:

* `extraction`
* `parsing`

## Supported Fields

Here is the current set of output / filter fields introduced by this plugin:

<!-- README-PLUGIN-FIELDS -->
|       NAME        |   TYPE   |       ARG       |                               DESCRIPTION                               |
|-------------------|----------|-----------------|-------------------------------------------------------------------------|
| `anomaly.count_min_sketch` | `uint64` | Key, Optional | Count Min Sketch Estimate according to the specified behavior profile for a predefined set of {syscalls} events. Access different behavior profiles/sketches using indices. For instance, anomaly.count_min_sketch[0] retrieves the first behavior profile defined in the plugins' `init_config`. |
| `anomaly.count_min_sketch.profile` | `string` | Key, Optional | Concatenated string according to the specified behavior profile (not preserving original order). Access different behavior profiles using indices. For instance, anomaly.count_min_sketch.profile[0] retrieves the first behavior profile defined in the plugins' `init_config`. |
| `anomaly.falco.duration_ns` | `uint64` | No Arg | Falco agent run duration in nanoseconds, which could be useful for ignoring some rare events at launch time while Falco is just starting to build up the counts in the sketch data structures (if applicable). |
<!-- /README-PLUGIN-FIELDS -->

## Usage

**Configuration**

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
            "fields": "%container.id %custom.proc.aname.lineage.join[7] %custom.proc.aexepath.lineage.join[7] %proc.tty %proc.vpgid.name %proc.sname",
            # execve, execveat exit event codes
            "event_codes": [293, 331],
            # optional config `reset_timer_ms`, resets the data structure every x milliseconds, here one hour as example
            # Remove JSON key if not wanted / needed.
            "reset_timer_ms": 3600000
          },
          {
            "fields": "%container.id %custom.proc.aname.lineage.join[7] %custom.proc.aexepath.lineage.join[7] %proc.tty %proc.vpgid.name %proc.sname %fd.name %fd.nameraw",
            # open, openat, openat2 exit event codes
            "event_codes": [3, 307, 327]
          },
          {
            "fields": "%container.id %proc.cmdline",
            # execve, execveat exit event codes
            "event_codes": [293, 331]
          }
        ]

load_plugins: [anomalydetection]
```

The first version is quite restrictive with respect to the behavior profile's `event_codes` and `fields`. In a nutshell, you can currently define them only for a handful of event codes that Falco supports and a subset of the [Supported Fields for Conditions and Outputs](https://falco.org/docs/reference/rules/supported-fields/).

**Behavior profiles for "execve*/clone*" events**

Example 1:
``` 
"event_codes": [293, 331],
```

Example 2:
``` 
"event_codes": [223, 335],
```

You can reference a behavior profile based on "execve*/clone*" events in any Falco rule that monitors any supported syscall. This works because every syscall is associated with a process.

**Behavior profiles for "fd-related" events**

Example 1:
```
rule: (evt.type in (open, openat, openat2) and evt.dir=<)
...
"event_codes": [3, 307, 327],
```

Example 2:
```
rule: (evt.type=connect and evt.dir=<)
...
"event_codes": [23],
```

You should avoid writing rules for arbitrary syscalls using "fd-related" behavior profiles because if a syscall doesn't involve a file descriptor (fd), referencing counts that rely on fd fields won't be meaningful.

Here's how it works:
- If your behavior profile includes `%fd.*` fields, all event codes in that profile must be related to file descriptors.
- If you use an "fd-related" behavior profile with a syscall that doesn't involve a file descriptor, the count will always be zero. While Falco won't crash, the anomaly detection estimate won't function as expected.

References:
- See the [Supported PPME `event codes`](#ppme-event-codes) reference below.
- See the [Supported Behavior Profiles `fields`](#behavior-profiles-fields) reference below.

**Open Parameters**:

This plugin does not have open params.

**Rules**

This plugin does not provide any default use cases or rules at the moment. More concrete use cases may be added at a later time.

Example of a dummy Falco rule using the `anomalydetection` fields for local testing:

```yaml
- macro: spawned_process
  condition: (evt.type in (execve, execveat) and evt.dir=<)
- rule: execve count_min_sketch test
  desc: "execve count_min_sketch test"
  condition: spawned_process and proc.name=cat and anomaly.count_min_sketch[0] > 10
  output: '%anomaly.count_min_sketch[0] %proc.pid %proc.ppid %proc.name %user.loginuid %user.name %user.uid %proc.cmdline %container.id %evt.type %evt.res %proc.cwd %proc.sid %proc.exepath %container.image.repository'
  priority: NOTICE
  tags: [maturity_sandbox, host, container, process, anomalydetection]
```

__NOTE__: Ensure you regularly execute `cat` commands. Once you have done so frequently enough, logs will start to appear. Alternatively, perform an inverse test to observe how quickly a very noisy rule gets silenced.

**Adoption**

To adopt the plugin framework, you can start by identifying rules in the [default](https://github.com/falcosecurity/rules) Falco ruleset that could benefit from auto-tuning based on your heuristics regarding counts. For example, you might broaden the scope of a rule and add an `anomaly.count_min_sketch` filter condition as a safety upper bound. 

For initial adoption, we recommend creating new, separate rules inspired by existing upstream rules, rather than modifying rules that are already performing well in production. 

Another approach is to duplicate a rule -- one version with and another without the anomaly detection filtering. 

Alternatively, you can add the count estimates as output fields to provide additional forensic evidence without using the counts for on-host filtering.

Lastly, keep in mind that there is a configuration to reset the counts per behavior profile every x milliseconds if this suits your use case better.

### Running

This plugin requires Falco with version >= **0.38.2**.
Modify the `falco.yaml` with the provided [configuration](#configuration) above and you are ready to go!

```shell
sudo falco -c falco.yaml -r falco_rules.yaml
```

## Local Development

### Build

```bash
git clone https://github.com/falcosecurity/plugins.git
cd plugins/plugins/anomalydetection
rm -f libanomalydetection.so; 
rm -f build/libanomalydetection.so; 
make;
# Copy the shared library to the expected location for `falco.yaml`, which is `library_path: libanomalydetection.so`
sudo mkdir -p /usr/share/falco/plugins/;
sudo cp -f libanomalydetection.so /usr/share/falco/plugins/libanomalydetection.so;
```


## References

### PPME event codes

Read this [blog post](https://falco.org/blog/adaptive-syscalls-selection/) to learn more about Falco's internal PPME event codes compared to the syscall names you are used to using in Falco rules.

```CPP
typedef enum {
	PPME_SYSCALL_OPEN_X = 3, // compare to "(evt.type=open and evt.dir=<)" in a Falco rule
	PPME_SOCKET_CONNECT_X = 23, // compare to "(evt.type=connect and evt.dir=<)" in a Falco rule
	PPME_SYSCALL_CREAT_X = 59, // compare to "(evt.type=creat and evt.dir=<)" in a Falco rule
	PPME_SYSCALL_CLONE_20_X = 223, // compare to "(evt.type=clone and evt.dir=<)" in a Falco rule
	PPME_SOCKET_ACCEPT_5_X = 247, // compare to "(evt.type=accept and evt.dir=<)" in a Falco rule
	PPME_SYSCALL_EXECVE_19_X = 293, // compare to "(evt.type=execve and evt.dir=<)" in a Falco rule
	PPME_SYSCALL_OPENAT_2_X = 307, // compare to "(evt.type=openat and evt.dir=<)" in a Falco rule
	PPME_SYSCALL_OPENAT2_X = 327, // compare to "(evt.type=openat2 and evt.dir=<)" in a Falco rule
	PPME_SYSCALL_EXECVEAT_X = 331, // compare to "(evt.type=execveat and evt.dir=<)" in a Falco rule
	PPME_SYSCALL_CLONE3_X = 335, // compare to "(evt.type=clone3 and evt.dir=<)" in a Falco rule
	PPME_SYSCALL_OPEN_BY_HANDLE_AT_X = 337, // compare to "(evt.type=open_by_handle_at and evt.dir=<)" in a Falco rule
	PPME_SOCKET_ACCEPT4_6_X = 389, // compare to "(evt.type=accept4 and evt.dir=<)" in a Falco rule
} ppm_event_code;
```

### Behavior Profiles fields

Compare to [Supported Fields for Conditions and Outputs](https://falco.org/docs/reference/rules/supported-fields/).

| Supported Behavior Profile Field | Description |
| --- | --- |
|proc.exe|The first command-line argument (i.e., argv[0]), typically the executable name or a custom string as specified by the user. It is primarily obtained from syscall arguments, truncated after 4096 bytes, or, as a fallback, by reading /proc/PID/cmdline, in which case it may be truncated after 1024 bytes. This field may differ from the last component of proc.exepath, reflecting how command invocation and execution paths can vary.|
|proc.pexe|The proc.exe (first command line argument argv[0]) of the parent process.|
|proc.aexe|The proc.exe (first command line argument argv[0]) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aexe[1] retrieves the proc.exe of the parent process, proc.aexe[2] retrieves the proc.exe of the grandparent process, and so on. The current process's proc.exe line can be obtained using proc.aexe[0]. When used without any arguments, proc.aexe is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aexe endswith java` to match any process ancestor whose proc.exe ends with the term `java`.|
|proc.exepath|The full executable path of a process, resolving to the canonical path for symlinks. This is primarily obtained from the kernel, or as a fallback, by reading /proc/PID/exe (in the latter case, the path is truncated after 1024 bytes). For eBPF drivers, due to verifier limits, path components may be truncated to 24 for legacy eBPF on kernel <5.2, 48 for legacy eBPF on kernel >=5.2, or 96 for modern eBPF.|
|proc.pexepath|The proc.exepath (full executable path) of the parent process.|
|proc.aexepath|The proc.exepath (full executable path) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aexepath[1] retrieves the proc.exepath of the parent process, proc.aexepath[2] retrieves the proc.exepath of the grandparent process, and so on. The current process's proc.exepath line can be obtained using proc.aexepath[0]. When used without any arguments, proc.aexepath is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aexepath endswith java` to match any process ancestor whose path ends with the term `java`.|
|proc.name|The process name (truncated after 16 characters) generating the event (task->comm). Truncation is determined by kernel settings and not by Falco. This field is collected from the syscalls args or, as a fallback, extracted from /proc/PID/status. The name of the process and the name of the executable file on disk (if applicable) can be different if a process is given a custom name which is often the case for example for java applications.|
|proc.pname|The proc.name truncated after 16 characters) of the process generating the event.|
|proc.aname|The proc.name (truncated after 16 characters) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.aname[1] retrieves the proc.name of the parent process, proc.aname[2] retrieves the proc.name of the grandparent process, and so on. The current process's proc.name line can be obtained using proc.aname[0]. When used without any arguments, proc.aname is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.aname=bash` to match any process ancestor whose name is `bash`.|
|proc.args|The arguments passed on the command line when starting the process generating the event excluding argv[0] (truncated after 4096 bytes). This field is collected from the syscalls args or, as a fallback, extracted from /proc/PID/cmdline.|
|proc.cmdline|The concatenation of `proc.name + proc.args` (truncated after 4096 bytes) when starting the process generating the event.|
|proc.pcmdline|The proc.cmdline (full command line (proc.name + proc.args)) of the parent of the process generating the event.|
|proc.acmdline|The full command line (proc.name + proc.args) for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.acmdline[1] retrieves the full command line of the parent process, proc.acmdline[2] retrieves the proc.cmdline of the grandparent process, and so on. The current process's full command line can be obtained using proc.acmdline[0]. When used without any arguments, proc.acmdline is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.acmdline contains base64` to match any process ancestor whose command line contains the term base64.|
|proc.cmdnargs|The number of command line args (proc.args).|
|proc.cmdlenargs|The total count of characters / length of the command line args (proc.args) combined excluding whitespaces between args.|
|proc.exeline|The full command line, with exe as first argument (proc.exe + proc.args) when starting the process generating the event.|
|proc.env|The environment variables of the process generating the event as concatenated string 'ENV_NAME=value ENV_NAME1=value1'. Can also be used to extract the value of a known env variable, e.g. proc.env[ENV_NAME].|
|proc.cwd|The current working directory of the event.|
|proc.tty|The controlling terminal of the process. 0 for processes without a terminal.|
|proc.pid|The id of the process generating the event.|
|proc.ppid|The pid of the parent of the process generating the event.|
|proc.apid|The pid for a specific process ancestor. You can access different levels of ancestors by using indices. For example, proc.apid[1] retrieves the pid of the parent process, proc.apid[2] retrieves the pid of the grandparent process, and so on. The current process's pid can be obtained using proc.apid[0]. When used without any arguments, proc.apid is applicable only in filters and matches any of the process ancestors. For instance, you can use `proc.apid=1337` to match any process ancestor whose pid is equal to 1337.|
|proc.vpid|The id of the process generating the event as seen from its current PID namespace.|
|proc.pvpid|The id of the parent process generating the event as seen from its current PID namespace.|
|proc.sid|The session id of the process generating the event.|
|proc.sname|The name of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process.|
|proc.sid.exe|The first command line argument argv[0] (usually the executable name or a custom one) of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process.|
|proc.sid.exepath|The full executable path of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process.|
|proc.vpgid|The process group id of the process generating the event, as seen from its current PID namespace.|
|proc.vpgid.name|The name of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights.|
|proc.vpgid.exe|The first command line argument argv[0] (usually the executable name or a custom one) of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights.|
|proc.vpgid.exepath|The full executable path of the current process's process group leader. This is either the process with proc.vpgid == proc.vpid or the eldest ancestor that has the same vpgid as the current process. The description of `proc.is_vpgid_leader` offers additional insights.|
|proc.is_exe_writable|'true' if this process' executable file is writable by the same user that spawned the process.|
|proc.is_exe_upper_layer|'true' if this process' executable file is in upper layer in overlayfs. This field value can only be trusted if the underlying kernel version is greater or equal than 3.18.0, since overlayfs was introduced at that time.|
|proc.is_exe_from_memfd|'true' if the executable file of the current process is an anonymous file created using memfd_create() and is being executed by referencing its file descriptor (fd). This type of file exists only in memory and not on disk. Relevant to detect malicious in-memory code injection. Requires kernel version greater or equal to 3.17.0.|
|proc.is_sid_leader|'true' if this process is the leader of the process session, proc.sid == proc.vpid. For host processes vpid reflects pid.|
|proc.is_vpgid_leader|'true' if this process is the leader of the virtual process group, proc.vpgid == proc.vpid. For host processes vpgid and vpid reflect pgid and pid. Can help to distinguish if the process was 'directly' executed for instance in a tty (similar to bash history logging, `is_vpgid_leader` would be 'true') or executed as descendent process in the same process group which for example is the case when subprocesses are spawned from a script (`is_vpgid_leader` would be 'false').|
|proc.exe_ino|The inode number of the executable file on disk. Can be correlated with fd.ino.|
|proc.exe_ino.ctime|Last status change time of executable file (inode->ctime) as epoch timestamp in nanoseconds. Time is changed by writing or by setting inode information e.g. owner, group, link count, mode etc.|
|proc.exe_ino.mtime|Last modification time of executable file (inode->mtime) as epoch timestamp in nanoseconds. Time is changed by file modifications, e.g. by mknod, truncate, utime, write of more than zero bytes etc. For tracking changes in owner, group, link count or mode, use proc.exe_ino.ctime instead.|
|container.id|The truncated container ID (first 12 characters), e.g. 3ad7b26ded6d is extracted from the Linux cgroups by Falco within the kernel. Consequently, this field is reliably available and serves as the lookup key for Falco's synchronous or asynchronous requests against the container runtime socket to retrieve all other `'container.*'` information. One important aspect to be aware of is that if the process occurs on the host, meaning not in the container PID namespace, this field is set to a string called 'host'. In Kubernetes, pod sandbox container processes can exist where `container.id` matches `k8s.pod.sandbox_id`, lacking other 'container.*' details.|
|fd.num|the unique number identifying the file descriptor.|
|fd.name|FD full name. If the fd is a file, this field contains the full path. If the FD is a socket, this field contain the connection tuple.|
|fd.directory|If the fd is a file, the directory that contains it.|
|fd.filename|If the fd is a file, the filename without the path.|
|fd.dev|device number (major/minor) containing the referenced file|
|fd.ino|inode number of the referenced file|
|fd.nameraw|FD full name raw. Just like fd.name, but only used if fd is a file path. File path is kept raw with limited sanitization and without deriving the absolute path.|
|custom.proc.aname.lineage.join|[Incubating] String concatenate the process lineage to achieve better performance. It requires an argument to specify the maximum level of traversal, e.g. 'custom.proc.aname.lineage.join[7]'. This is a custom plugin specific field for the anomaly behavior profiles only. It may be dperecated in the future.|
|custom.proc.aexe.lineage.join|[Incubating] String concatenate the process lineage to achieve better performance. It requires an argument to specify the maximum level of traversal, e.g. 'custom.proc.aexe.lineage.join[7]'. This is a custom plugin specific field for the anomaly behavior profiles only. It may be dperecated in the future.|
|custom.proc.aexepath.lineage.join|[Incubating] String concatenate the process lineage to achieve better performance. It requires an argument to specify the maximum level of traversal, e.g. 'custom.proc.aexepath.lineage.join[7]'. This is a custom plugin specific field for the anomaly behavior profiles only. It may be dperecated in the future.|
|custom.fd.name.part1|[Incubating] For fd related network events only. Part 1 as string of the ip tuple in the format 'ip:port', e.g '172.40.111.222:54321' given fd.name '172.40.111.222:54321->142.251.111.147:443'. It may be dperecated in the future.|
|custom.fd.name.part2|[Incubating] For fd related network events only. Part 2 as string of the ip tuple in the format 'ip:port', e.g.'142.251.111.147:443' given fd.name '172.40.111.222:54321->142.251.111.147:443'. This is a custom plugin specific field for the anomaly behavior profiles only. It may be dperecated in the future.|
