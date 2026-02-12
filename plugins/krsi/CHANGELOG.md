# Changelog

## v0.1.0

* [`28618ac`](https://github.com/falcosecurity/plugins/commit/28618ac2) fix(plugins/krsi): fix plugin version

* [`d09985d`](https://github.com/falcosecurity/plugins/commit/d09985d5) fix(plugins/krsi): correct multi-arch char type handling

* [`b9c6b0a`](https://github.com/falcosecurity/plugins/commit/b9c6b0a4) fix(.github): pin deps to build rust ebpf

* [`40f892b`](https://github.com/falcosecurity/plugins/commit/40f892bf) fix(plugins/krsi): correct makefile

* [`6da6129`](https://github.com/falcosecurity/plugins/commit/6da61290) cleanup(krsi): add license text, remove leftover

* [`3c8710e`](https://github.com/falcosecurity/plugins/commit/3c8710ef) chore: add `Makefile`

* [`303fd1e`](https://github.com/falcosecurity/plugins/commit/303fd1eb) doc: populate `README.md`

* [`9b6951a`](https://github.com/falcosecurity/plugins/commit/9b6951aa) feat: add example rule file

* [`52a089c`](https://github.com/falcosecurity/plugins/commit/52a089c5) feat(ebpf): add `unlink` and `unlinkat` syscall support

* [`178a7a3`](https://github.com/falcosecurity/plugins/commit/178a7a3d) fix(ebpf): prevent `symlinkat` syscall evt gen if support is disabled

* [`ce3c427`](https://github.com/falcosecurity/plugins/commit/ce3c4271) fix(ebpf): prevent `renameat` syscall event gen if support is disabled

* [`6070c05`](https://github.com/falcosecurity/plugins/commit/6070c05c) fix(ebpf): prevent `mkdirat` syscall event gen if support is disabled

* [`99f0e94`](https://github.com/falcosecurity/plugins/commit/99f0e94b) fix(ebpf): prevent `linkat` syscall event gen if support is disabled

* [`53542ab`](https://github.com/falcosecurity/plugins/commit/53542abc) feat: add plugin options support

* [`2b5e4c5`](https://github.com/falcosecurity/plugins/commit/2b5e4c5d) feat(krsi): add connect operation and thread fields support

* [`e9a9999`](https://github.com/falcosecurity/plugins/commit/e9a9999d) test(ebpf): add `load_and_attach_programs` test

* [`4022aa5`](https://github.com/falcosecurity/plugins/commit/4022aa5d) refactor(ebpf): remove unneded vmlinux module

* [`93bfe63`](https://github.com/falcosecurity/plugins/commit/93bfe630) feat(ebpf): use CO-RE approach to evaluate inode upper dentry

* [`e53017b`](https://github.com/falcosecurity/plugins/commit/e53017b8) refactor(ebpf): remove some vmlinux references

* [`f5b6730`](https://github.com/falcosecurity/plugins/commit/f5b67304) feat(ebpf): replace non-CO-RE access to `f_path` with CO-RE one

* [`280f318`](https://github.com/falcosecurity/plugins/commit/280f318d) feat(ebpf): add iou_ret field to open event

* [`ec628cf`](https://github.com/falcosecurity/plugins/commit/ec628cf5) feat(ebpf): add partial bind operations support

* [`0bf13c4`](https://github.com/falcosecurity/plugins/commit/0bf13c4a) feat(test): add Dockerfile

* [`5e54860`](https://github.com/falcosecurity/plugins/commit/5e548605) feat: integrate plugin with eBPF and add userspace fields handling

* [`010a67e`](https://github.com/falcosecurity/plugins/commit/010a67ec) refactor: cleanup code

* [`4e4bb8c`](https://github.com/falcosecurity/plugins/commit/4e4bb8c7) feat(ebpf): replace io_uring structs accesses with CO-RE equivalents

* [`270cae3`](https://github.com/falcosecurity/plugins/commit/270cae32) feat(ebpf): replace `file->private_data` access with CO-RE equivalent

* [`a6c5e95`](https://github.com/falcosecurity/plugins/commit/a6c5e954) refactor(ebpf): remove unused `file_name` non-CO-RE extractor

* [`21eebf5`](https://github.com/falcosecurity/plugins/commit/21eebf5c) feat(ebpf): replace `filename_name` non-CO-RE extractor

* [`1a58474`](https://github.com/falcosecurity/plugins/commit/1a584742) feat(ebpf): use CO-RE accessors for some sockets accesses

* [`adafbd2`](https://github.com/falcosecurity/plugins/commit/adafbd22) feat(ebpf): use CO-RE accessors for some files accesses

* [`751ae3b`](https://github.com/falcosecurity/plugins/commit/751ae3bc) feat(ebpf): add C binding infrastructure enabling CO-RE

* [`1e88c07`](https://github.com/falcosecurity/plugins/commit/1e88c07c) refactor(ebpf): move extraction in `extractors` and `getters` crates

* [`8a7be7f`](https://github.com/falcosecurity/plugins/commit/8a7be7f6) refactor(ebpf): add sockets::extract crate

* [`abca308`](https://github.com/falcosecurity/plugins/commit/abca308d) feat(ebpf): add renameat operations support

* [`8ac597f`](https://github.com/falcosecurity/plugins/commit/8ac597fe) feat(ebpf): add mkdirat operations support

* [`036828b`](https://github.com/falcosecurity/plugins/commit/036828b9) refactor(ebpf): use declarative approach to load and attach programs

* [`da57e8d`](https://github.com/falcosecurity/plugins/commit/da57e8df) fix: safe parse_ringbuf_event

* [`a301d3e`](https://github.com/falcosecurity/plugins/commit/a301d3e7) style: apply code-formatting

* [`0354b3d`](https://github.com/falcosecurity/plugins/commit/0354b3d5) chore: add `pre-commit` hooks for enforcing coding style and policies

* [`4903b39`](https://github.com/falcosecurity/plugins/commit/4903b391) feat(ebpf): add unlinkat io_uring operation support

* [`b4feb0b`](https://github.com/falcosecurity/plugins/commit/b4feb0b1) feat(ebpf): add linkat operations support

* [`24629d8`](https://github.com/falcosecurity/plugins/commit/24629d88) refactor(ebpf): move file-related extraction logics to separate crate

* [`b9a0d7f`](https://github.com/falcosecurity/plugins/commit/b9a0d7f2) refactor(ebpf): align symlinkat operation map name

* [`2dec519`](https://github.com/falcosecurity/plugins/commit/2dec5194) refactor(ebpf): align connect operation handling code naming

* [`53dc445`](https://github.com/falcosecurity/plugins/commit/53dc4459) refactor(ebpf): cleanup open operation handling code

* [`db523d8`](https://github.com/falcosecurity/plugins/commit/db523d88) refactor(ebpf): rename open operation's pids map

* [`0afb3c6`](https://github.com/falcosecurity/plugins/commit/0afb3c6b) feat: move ebpf support in different crate and introduce feature flags

* [`4bbea65`](https://github.com/falcosecurity/plugins/commit/4bbea658) fix: adjust open's `name` param output positioning

* [`b991bac`](https://github.com/falcosecurity/plugins/commit/b991bac3) feat: add testing program

* [`32629e6`](https://github.com/falcosecurity/plugins/commit/32629e67) feat(ebpf): add symlinkat operations support

* [`b9b0407`](https://github.com/falcosecurity/plugins/commit/b9b04078) feat(ebpf): export `iou_ret` in connect operation

* [`a8e7d5f`](https://github.com/falcosecurity/plugins/commit/a8e7d5f3) feat(ebpf): add socket operations support

* [`d4985b5`](https://github.com/falcosecurity/plugins/commit/d4985b52) feat(ebpf): introduce `iouring` module from data extraction

* [`803bca3`](https://github.com/falcosecurity/plugins/commit/803bca3a) feat(ebpf): avoid sending fd/file_index if not present

* [`ba8d9ae`](https://github.com/falcosecurity/plugins/commit/ba8d9aef) feat(ebpf): remove need for socket permanent file descriptors tracking

* [`ce568f4`](https://github.com/falcosecurity/plugins/commit/ce568f41) refactor(ebpf): split eBPF programs by operation

* [`129e5c1`](https://github.com/falcosecurity/plugins/commit/129e5c1c) feat(ebpf): drop some `unsafe` method qualifiers in auxmap

* [`9b06ae2`](https://github.com/falcosecurity/plugins/commit/9b06ae20) feat(ebpf): add support for io_uring connect operation

* [`22f21ad`](https://github.com/falcosecurity/plugins/commit/22f21ad7) feat(ebpf): add io_uring's `IORING_OPENAT{2}` `file_index` support

* [`68aa11b`](https://github.com/falcosecurity/plugins/commit/68aa11b9) feat(ebpf): add non-blocking connect operations support

* [`96d7746`](https://github.com/falcosecurity/plugins/commit/96d7746e) style(ebpf): remove non idiomatic `_ptr` suffixes

* [`cc54966`](https://github.com/falcosecurity/plugins/commit/cc549664) feat(ebpf): add connect support

* [`99c7f3d`](https://github.com/falcosecurity/plugins/commit/99c7f3dd) refactor(ebpf): replace `tid` with `pid`

* [`4c44415`](https://github.com/falcosecurity/plugins/commit/4c444157) feat(ebpf): add socket creation monitoring support

* [`0cea86b`](https://github.com/falcosecurity/plugins/commit/0cea86b2) fix(ebpf): reintroduce support for io_uring openat* operations

* [`d245d66`](https://github.com/falcosecurity/plugins/commit/d245d66c) refactor(krsi): cleanup

* [`0913bfa`](https://github.com/falcosecurity/plugins/commit/0913bfa7) doc(ebpf): fix `open` module documentation

* [`f0a399d`](https://github.com/falcosecurity/plugins/commit/f0a399d7) fix(ebpf): fix auxiliary map index calculation

* [`11e6949`](https://github.com/falcosecurity/plugins/commit/11e69492) fix(ebpf): fix timestamp calculation by including boot time

* [`c8596ce`](https://github.com/falcosecurity/plugins/commit/c8596ce0) refactor(ebpf): move file opening extraction in separate module

* [`2d9f21c`](https://github.com/falcosecurity/plugins/commit/2d9f21ce) fix(ebpf): handle `fd_install` invocations only in open context

* [`75cc932`](https://github.com/falcosecurity/plugins/commit/75cc932f) feat(krsi): populate fd table

* [`a690118`](https://github.com/falcosecurity/plugins/commit/a690118a) feat: handle io_uring thread

* [`9661fe7`](https://github.com/falcosecurity/plugins/commit/9661fe7d) feat(ebpf): export tgid together with pid in event header

* [`e348237`](https://github.com/falcosecurity/plugins/commit/e348237e) fix(ebpf): remove early return behaviour

* [`8ff297c`](https://github.com/falcosecurity/plugins/commit/8ff297c8) feat(krsi): add extractor fields

* [`b084b02`](https://github.com/falcosecurity/plugins/commit/b084b02f) feat(ebpf): enable full path resolution

* [`c70b746`](https://github.com/falcosecurity/plugins/commit/c70b746e) feat(ebpf): align the auxiliary maps number to the number of CPUs

* [`91e307c`](https://github.com/falcosecurity/plugins/commit/91e307c1) feat: add integration between eBPF and plugin

* [`cb6f03c`](https://github.com/falcosecurity/plugins/commit/cb6f03c0) feat: add eBPF source

* [`ddf3f6c`](https://github.com/falcosecurity/plugins/commit/ddf3f6cf) feat: initial scaffolding and plugin setup


