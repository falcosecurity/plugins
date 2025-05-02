# Falco KRSI Integration

This plugin allows Falco to receive data from the Kernel Runtime Security Instrumentation system.

The main difference between these operations and regular Falco events is that:
* With `krsi` operations Falco can inspect both syscall and [io_uring](https://www.man7.org/linux/man-pages/man7/io_uring.7.html) activity, which you wouldn't be able to do with just syscalls (configurable)
* The arguments are collected directly from the kernel, making data collection more resilient against TOCTOU attacks and other conditions that could prevent Falco from getting accurate data
* File path and network connection data resolution is performed directly in the kernel to provide more accurate information

## Supported fields

<!-- README-PLUGIN-FIELDS -->
|       NAME        |   TYPE   | ARG  |                                                                                                               DESCRIPTION                                                                                                               |
|-------------------|----------|------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `krsi.name`       | `string` | None | Availability: `krsi_open`, `krsi_connect`.<br/>Per-event descriptions:<br/>- `krsi_open`: full path to file<br/>- `krsi_connect`: connection display name (e.g. `127.0.0.1:54321->10.0.0.1:8000`)                                       |
| `krsi.fd`         | `uint64` | None | Availability: `krsi_open`, `krsi_socket`, `krsi_connect`.<br/>Description: fd number (if available)                                                                                                                                     |
| `krsi.file_index` | `uint64` | None | Availability: `krsi_open`, `krsi_socket`, `krsi_connect`.<br/>Description: file index number (if available)                                                                                                                             |
| `krsi.flags`      | `uint64` | None | Availability: `krsi_open`, `krsi_linkat`, `krsi_unlinkat`.<br/>Per-event descriptions:<br/>- `krsi_open`: open* flags, equivalent to open* syscall family flags<br/>- `krsi_linkat`: linkat flags<br/>- `krsi_unlinkat`: unlinkat flags |
| `krsi.mode`       | `uint64` | None | Availability: `krsi_open`, `krsi_mkdirat`.<br/>Per-event descriptions:<br/>- `krsi_open`: open file mode<br/>- `krsi_mkdirat`: mkdirat mode, indicating permission to use                                                               |
| `krsi.dev`        | `uint64` | None | Availability: `krsi_open`.<br/>Per-event descriptions:<br/>- `krsi_open`: file device number                                                                                                                                            |
| `krsi.ino`        | `uint64` | None | Availability: `krsi_open`.<br/>Per-event descriptions:<br/>- `krsi_open`: file inode number                                                                                                                                             |
| `krsi.domain`     | `uint64` | None | Availability: `krsi_socket`.<br/>Per-event descriptions:<br/>- `krsi_socket`: socket domain                                                                                                                                             |
| `krsi.type`       | `uint64` | None | Availability: `krsi_socket`.<br/>Per-event descriptions:<br/>- `krsi_socket`: socket type                                                                                                                                               |
| `krsi.iou_ret`    | `uint64` | None | Availability: `krsi_open`, `krsi_socket`, `krsi_connect`, `krsi_symlinkat`, `krsi_linkat`, `krsi_unlinkat`, `krsi_mkdirat`.<br/>Description: io_uring internal return value (if available)                                              |
| `krsi.res`        | `uint64` | None | Availability: `krsi_connect`, `krsi_symlinkat`, `krsi_linkat`, `krsi_unlinkat`, `krsi_mkdirat`.<br/>Description: `operation return value (if available)                                                                                 |
| `krsi.target`     | `string` | None | Availability: `krsi_symlinkat`.<br/>Per-event descriptions:<br/>- `krsi_symlinkat`: symbolic link target path                                                                                                                           |
| `krsi.linkdirfd`  | `uint64` | None | Availability: `krsi_symlinkat`.<br/>Per-event descriptions:<br/>- `krsi_symlinkat`: symbolic link dir fd                                                                                                                                |
| `krsi.linkpath`   | `string` | None | Availability: `krsi_symlinkat`.<br/>Per-event descriptions:<br/>- `krsi_symlinkat`: symbolic link path                                                                                                                                  |
| `krsi.olddirfd`   | `uint64` | None | Availability: `krsi_linkat`.<br/>Per-event descriptions:<br/>- `krsi_linkat`: dir fd for the target path                                                                                                                                |
| `krsi.newdirfd`   | `uint64` | None | Availability: `krsi_linkat`.<br/>Per-event descriptions:<br/>- `krsi_linkat`: dir fd for the link path                                                                                                                                  |
| `krsi.dirfd`      | `uint64` | None | Availability: `krsi_unlinkat`, `krsi_mkdirat`.<br/>Description: dir fd of the path                                                                                                                                                      |
| `krsi.path`       | `string` | None | Availability: `krsi_unlinkat`, `krsi_mkdirat`.<br/>Per-event descriptions:<br/>- `krsi_unlinkat`: path to be unlinked<br/>- `krsi_mkdirat`: path to the directory to be created                                                         |
| `krsi.oldpath`    | `string` | None | Availability: `krsi_linkat`.<br/>Per-event descriptions:<br/>- `krsi_linkat`: target path                                                                                                                                               |
| `krsi.newpath`    | `string` | None | Availability: `krsi_linkat`.<br/>Per-event descriptions:<br/>- `krsi_linkat`: link path                                                                                                                                                 |
| `krsi.cip`        | `ipaddr` | None | Availability: `krsi_connect`.<br/>Per-event descriptions:<br/>- `krsi_connect`: client IP address                                                                                                                                       |
| `krsi.sip`        | `ipaddr` | None | Availability: `krsi_connect`.<br/>Per-event descriptions:<br/>- `krsi_connect`: server IP address                                                                                                                                       |
| `krsi.cport`      | `uint64` | None | Availability: `krsi_connect`.<br/>Per-event descriptions:<br/>- `krsi_connect`: client port                                                                                                                                             |
| `krsi.sport`      | `uint64` | None | Availability: `krsi_connect`.<br/>Per-event descriptions:<br/>- `krsi_connect`: server port                                                                                                                                             |
<!-- /README-PLUGIN-FIELDS -->

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

See the [repo corresponding section](../../README.md#enforcing-coding-style-and-repo-policies-locally) for more details.
