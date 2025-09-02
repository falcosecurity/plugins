# Changelog

## dev build (unreleased)

* [`ef13f88`](https://github.com/falcosecurity/plugins/commit/ef13f887) build(deps): bump slab from 0.4.10 to 0.4.11 in /plugins/krsi

* [`8d44358`](https://github.com/falcosecurity/plugins/commit/8d44358d) build(plugins/krsi): bump `cargo_metadata` from 0.19.0 to 0.20.0

* [`d4e8eb2`](https://github.com/falcosecurity/plugins/commit/d4e8eb2f) feat(plugins/krsi): add initial `renameat` parsing/extraction support

* [`9fd1d28`](https://github.com/falcosecurity/plugins/commit/9fd1d28b) refactor(plugins/krsi): remove redundant parts and rephrase README.md

* [`56ec9a8`](https://github.com/falcosecurity/plugins/commit/56ec9a81) refactor(plugins/krsi): rename example file as `example_rules.yaml`

* [`c358225`](https://github.com/falcosecurity/plugins/commit/c358225d) refactor(plugins/krsi/krsi): split event parsing into dedicated funcs

* [`b56ce0a`](https://github.com/falcosecurity/plugins/commit/b56ce0aa) refactor(plugins/krsi/krsi): fix extracted field desc formatting

* [`400cdcb`](https://github.com/falcosecurity/plugins/commit/400cdcbb) fix(plugins/krsi): properly handle `auxbuf` writing errors

* [`53ba10d`](https://github.com/falcosecurity/plugins/commit/53ba10dd) refactor(plugins/krsi): remove `auxbuf` unsafe code using `zerocopy`

* [`54c8287`](https://github.com/falcosecurity/plugins/commit/54c82871) fix(plugins/krsi): use safe ring buffer events parsing logic

* [`2e7dff5`](https://github.com/falcosecurity/plugins/commit/2e7dff5a) refactor(plugins/krsi/krsi): use macros for field extraction

* [`e53b45e`](https://github.com/falcosecurity/plugins/commit/e53b45e9) docs(plugins/krsi): add `ekoops` as maintainer

* [`f91ed60`](https://github.com/falcosecurity/plugins/commit/f91ed607) feat(plugins/krsi): add `protocol` field extraction support

* [`ae39190`](https://github.com/falcosecurity/plugins/commit/ae39190f) build(deps): bump tokio from 1.44.0 to 1.44.2 in /plugins/krsi

## v0.1.0

* [`28618ac`](https://github.com/falcosecurity/plugins/commit/28618ac2) fix(plugins/krsi): fix plugin version

* [`d09985d`](https://github.com/falcosecurity/plugins/commit/d09985d5) fix(plugins/krsi): correct multi-arch char type handling

* [`40f892b`](https://github.com/falcosecurity/plugins/commit/40f892bf) fix(plugins/krsi): correct makefile

* [`70562d8`](https://github.com/falcosecurity/plugins/commit/70562d85) new(krsi): add registry entry

* [`6da6129`](https://github.com/falcosecurity/plugins/commit/6da61290) cleanup(krsi): add license text, remove leftover

* [`2b5e4c5`](https://github.com/falcosecurity/plugins/commit/2b5e4c5d) feat(krsi): add connect operation and thread fields support

* [`d245d66`](https://github.com/falcosecurity/plugins/commit/d245d66c) refactor(krsi): cleanup

* [`75cc932`](https://github.com/falcosecurity/plugins/commit/75cc932f) feat(krsi): populate fd table

* [`8ff297c`](https://github.com/falcosecurity/plugins/commit/8ff297c8) feat(krsi): add extractor fields


