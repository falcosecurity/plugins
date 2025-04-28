# Falco KRSI Integration

This plugin allows Falco to receive data from the Kernel Runtime Security Instrumentation system.

The main difference between these operations and regular Falco events is that:
* With `krsi` operations Falco can inspect both syscall and [io_uring](https://www.man7.org/linux/man-pages/man7/io_uring.7.html) activity, which you wouldn't be able to do with just syscalls (configurable)
* The arguments are collected directly from the kernel, making data collection more resilient against TOCTOU attacks and other conditions that could prevent Falco from getting accurate data
* File path and network connection data resolution is performed directly in the kernel to provide more accurate information

It generates the following types of events with parameters:
* `krsi_open`: open operation, only generated if the operation is successful
  * `krsi.name` (string) : full path to file
  * `krsi.fd` (int) : fd number
  * `krsi.file_index` (int) : file index (if available)
  * `krsi.flags` (int) : flags (same as a regular file open from the Falco instrumentation)
  * `krsi.mode` (int) : file mode
  * `krsi.dev` (int) : device number
  * `krsi.ino` (int) : inode number
  * `krsi.iou_ret` (int) : io_uring return value (if available)
* `krsi_socket`: 
  * `krsi.fd` (int) : fd number (if available)
  * `krsi.domain` (int) : socket domain
  * `krsi.type` (int) : socket type
  * `krsi.file_index` (int) : file index (if available)
  * `krsi.iou_ret` (int) : io_uring return value (if available)
* `krsi_connect`: 
  * `krsi.fd` (int) : fd number (if available)
  * `krsi.file_index` (int) : file index number (if available)
  * `krsi.name` (string) : connection display name (e.g. `127.0.0.1:54321->10.0.0.1:8000`)
  * `krsi.res` (int) : operation result (if available)
  * `krsi.iou_ret` (int) : io_uring return value (if available)
  * `krsi.sip` (IP address): server IP
  * `krsi.sport` (int): server port
  * `krsi.cip` (IP address): client IP
  * `krsi.cport` (int): client port
* `krsi_symlinkat`: 
  * `krsi.target` (string) : target file name (oldpath)
  * `krsi.linkdirfd` (int) : link dirfd
  * `krsi.linkpath` (string) : link path
  * `krsi.res` (int) : operation result (if available)
  * `krsi.iou_ret` (int) : io_uring return value (if available)
* `krsi_linkat`:
  * `krsi.olddirfd` (int) : dir fd for the existing file
  * `krsi.oldpath` (string) : path to the existing file
  * `krsi.newdirfd` (int) : dir fd for the new link location
  * `krsi.newpath` (string) : path for the new link location
  * `krsi.flags` (int) : flags
  * `krsi.res` (int) : operation result (if available)
  * `krsi.iou_ret` (int) : io_uring return value (if available)
* `krsi_unlinkat`:
  * `krsi.path` (string) : operation path
  * `krsi.dirfd` (int) : dirfd
  * `krsi.flags` (int) : flags
  * `krsi.res` (int) : operation result (if available)
  * `krsi.iou_ret` (int) : io_uring return value (if available)
* `krsi_mkdirat`:
  * `krsi.path` (string) : operation path
  * `krsi.dirfd` (int) : dirfd
  * `krsi.mode` (int) : mode
  * `krsi.res` (int) : operation result (if available)
  * `krsi.iou_ret` (int) : io_uring return value (if available)

## Running and configuring the plugin

Run Falco with:

```bash
sudo /path/to/falco -o 'plugins[]={"name":"krsi","library_path":"/path/to/libkrsi.so","init_config":{"io_uring":true}}' -o load_plugins[]=krsi
```

To enable `io_uring` collection. Change the configuration to `{"io_uring":true,"syscall":true}` to collect both io_uring and syscall activity. You can then load rule files that use these events.

## Example rule

```yaml
- rule: KRSI open
  desc: KRSI open
  condition: evt.type = krsi_open
  output: "[KRSI OPEN] iouring-poc %proc.pid:%thread.tid (name: %proc.name) %krsi.filename"
  priority: INFO
```

See the [example_rule](example_rule.yaml) file for more information.

## How to build and run the plugin

### Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

To build the plugin, run

```shell
cargo build
```

To load the plugin in Falco, run:

```shell
sudo /path/to/falco -o 'plugins[]={"name":"krsi","library_path":"/path/to/libkrsi.so","init_config":{"io_uring":true}}' -o load_plugins[]=krsi
```

## Example rule

```yaml
- rule: KRSI open
  desc: KRSI open
  condition: evt.type = krsi_open
  output: "[KRSI OPEN] iouring-poc %proc.pid:%thread.tid (name: %proc.name) %krsi.filename"
  priority: INFO
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/krsi` can be
copied to a Linux server or VM and run there.

## How to contribute

### Local testing

A small utility to generate syscalls/io_uring events is provided under `test/`. See [test/README.md](./test/README.md) for more details.

### Enforcing coding style and repo policies locally

This repo supports enforcing coding style and policies locally through the `pre-commit` framework. `pre-commit` allows
you to automatically install `git-hooks` that will be executed at every new commit. The following is the list of
`git-hooks` defined in `.pre-commit-config.yaml`:
1. the `rust-fmt` hook - a `pre-commit` git hook running `rust fmt` on the staged changes
2. the `dco` hook - a `pre-commit-msg` git hook running adding the `DCO` on the commit if not present

The following steps describe how to install these hooks.

##### Step 1

Install `pre-commit` framework following the [official documentation](https://pre-commit.com/#installation).

> __Please note__: you have to follow only the "Installation" section.

#### Step 2

Install `pre-commit` git hooks:
```bash
pre-commit install --hook-type pre-commit --hook-type prepare-commit-msg  --overwrite
```
