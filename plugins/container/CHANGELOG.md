# Changelog

## v0.6.3

* [`fb2ad64`](https://github.com/falcosecurity/plugins/commit/fb2ad646) chore(plugins/container): bump to `v0.6.3`

* [`9a3ee4c`](https://github.com/falcosecurity/plugins/commit/9a3ee4c5) fix(plugins/container): correct image parsing with registry port


## v0.6.2

* [`4a4ea55`](https://github.com/falcosecurity/plugins/commit/4a4ea55c) chore(plugins/container): bump to v0.6.2

* [`807e3d6`](https://github.com/falcosecurity/plugins/commit/807e3d6b) build(deps): bump github.com/sigstore/fulcio

* [`365ae0a`](https://github.com/falcosecurity/plugins/commit/365ae0aa) deps(plugins/container): update k8s.io/cri-api and k8s.io/cri-client

* [`1d32f5c`](https://github.com/falcosecurity/plugins/commit/1d32f5c1) build(deps): bump github.com/sigstore/sigstore

* [`d1775b1`](https://github.com/falcosecurity/plugins/commit/d1775b1a) build(deps): bump github.com/opencontainers/selinux to 1.13.1

* [`14d243c`](https://github.com/falcosecurity/plugins/commit/14d243c6) build(deps): bump github.com/opencontainers/selinux

* [`bff3406`](https://github.com/falcosecurity/plugins/commit/bff34066) feat(container): cache resolution results

* [`a1de12e`](https://github.com/falcosecurity/plugins/commit/a1de12ea) chore(plugins/container): bump Go version to 1.25


## v0.6.1

* [`2ef9be1`](https://github.com/falcosecurity/plugins/commit/2ef9be15) chore(plugins/container): bump to `0.6.1`

* [`fb763af`](https://github.com/falcosecurity/plugins/commit/fb763af5) fix(container): prevent int64 overflow in JSON deserialization

* [`f4debc9`](https://github.com/falcosecurity/plugins/commit/f4debc99) perf(plugins/container): use string_view to reduce allocations in cgroup matc...

* [`73bdb47`](https://github.com/falcosecurity/plugins/commit/73bdb476) perf(plugins/container): optimize endswih in runc matcher

* [`0021125`](https://github.com/falcosecurity/plugins/commit/00211255) fix(container): don't allocate reflex matcher at every resolve

* [`3352cc2`](https://github.com/falcosecurity/plugins/commit/3352cc29) docs(plugins/container): add deepskyblue86 as a maintainer

* [`d25b110`](https://github.com/falcosecurity/plugins/commit/d25b110b) chore(plugins/container): fix formatting

* [`b822c11`](https://github.com/falcosecurity/plugins/commit/b822c113) ci(plugins/container): run container plugin integration test in ci

* [`521649a`](https://github.com/falcosecurity/plugins/commit/521649ad) chore(plugins/container): add integration test on extraction capability


## v0.6.0

* [`41cdbe1`](https://github.com/falcosecurity/plugins/commit/41cdbe1e) chore(plugins/container): bump to `v0.6.0`

* [`b49ad24`](https://github.com/falcosecurity/plugins/commit/b49ad240) fix: if missing thread_entry, don't attempt to dereference it (iss-1076)

* [`c8a839a`](https://github.com/falcosecurity/plugins/commit/c8a839a3) feat(container): add basic exposed fields


## v0.5.0

* [`b9784a0`](https://github.com/falcosecurity/plugins/commit/b9784a02) chore(plugins/container): bump to v0.5.0

* [`eac4150`](https://github.com/falcosecurity/plugins/commit/eac41509) build(deps): bump golang.org/x/crypto in /plugins/container/go-worker

* [`5737135`](https://github.com/falcosecurity/plugins/commit/5737135f) build(container): use MinGW toolchaing instead of MSVC on windows builds

* [`a167a1c`](https://github.com/falcosecurity/plugins/commit/a167a1ca) update(deps): move from github.com/containers/image/v5 to go.podman.io/image/v5

* [`87d5c72`](https://github.com/falcosecurity/plugins/commit/87d5c72e) update(deps): bump github.com/docker/docker from to v28.5.2+incompatible

* [`cb0d70b`](https://github.com/falcosecurity/plugins/commit/cb0d70b0) fix(container): add back support for Falco libs 0.21

* [`61df229`](https://github.com/falcosecurity/plugins/commit/61df229a) feat(plugins/container): add logging in go-worker engines

* [`81201c0`](https://github.com/falcosecurity/plugins/commit/81201c0e) fix(container): crash at filter extract

* [`874361f`](https://github.com/falcosecurity/plugins/commit/874361f4) build(deps): bump github.com/containerd/containerd/v2

* [`f44f4ea`](https://github.com/falcosecurity/plugins/commit/f44f4ea8) build(deps): bump github.com/opencontainers/runc


## v0.4.1

* [`f411492`](https://github.com/falcosecurity/plugins/commit/f411492a) chore(plugins/container): bump to v0.4.1

* [`d95e32c`](https://github.com/falcosecurity/plugins/commit/d95e32c3) fix(container): do not generate async event for CRI CONTAINER_STOPPED_EVENT

* [`025444d`](https://github.com/falcosecurity/plugins/commit/025444d3) chore(plugins/container): bump to v0.4.0


## v0.4.0-rc1


## v0.4.0

* [`025444d`](https://github.com/falcosecurity/plugins/commit/025444d3) chore(plugins/container): bump to v0.4.0

* [`3b0a2f1`](https://github.com/falcosecurity/plugins/commit/3b0a2f1a) chore(plugins/container): bump to v0.4.0-rc1

* [`f1e38d4`](https://github.com/falcosecurity/plugins/commit/f1e38d4b) feat(plugins/container)!: bump required schema version to `4.0.0`

* [`964a864`](https://github.com/falcosecurity/plugins/commit/964a864a) test(container/go-worker): fix flaky tests

* [`315ed46`](https://github.com/falcosecurity/plugins/commit/315ed46b) fix(container): cri sandbox detection

* [`c53e51f`](https://github.com/falcosecurity/plugins/commit/c53e51fc) fix(container): containerd sandbox detection

* [`880dc1d`](https://github.com/falcosecurity/plugins/commit/880dc1dc) chore(container): add microk8s to go-worker exe

* [`4802a10`](https://github.com/falcosecurity/plugins/commit/4802a103) build(plugins/container/go-worker): upgrade containerd to v2.1.4

* [`5986a0e`](https://github.com/falcosecurity/plugins/commit/5986a0e4) build(deps): bump github.com/containers/podman/v5

* [`3916d85`](https://github.com/falcosecurity/plugins/commit/3916d853) chore(plugins): bulk update to plugin-sdk-go to v0.8.3

* [`b3d9b6e`](https://github.com/falcosecurity/plugins/commit/b3d9b6e6) build(deps): bump github.com/ulikunitz/xz


## v0.3.7

* [`3a40e6e`](https://github.com/falcosecurity/plugins/commit/3a40e6e7) chore(plugins/container): bump to v0.3.7

* [`61cdb3f`](https://github.com/falcosecurity/plugins/commit/61cdb3f0) fix(plugins/container): safe access to `podSandboxStatus` in CRI engine to pr...

* [`3fc8fde`](https://github.com/falcosecurity/plugins/commit/3fc8fde4) fix(plugins/container): prevent segfault in docker engine List method

* [`c27ad53`](https://github.com/falcosecurity/plugins/commit/c27ad53c) fix(plugins/container): prevent CRI engine goroutine deadlock during shutdown

* [`932e308`](https://github.com/falcosecurity/plugins/commit/932e3086) fix(plugins/container): static linking libgcc/libstdc++ for legacy compatibility


## v0.3.6

* [`eb04abf`](https://github.com/falcosecurity/plugins/commit/eb04abf2) new(plugins/container): add pprof to go-worker demo executable.

* [`421197c`](https://github.com/falcosecurity/plugins/commit/421197c1) chore(plugins/container): inline container_health_probe

* [`755ec40`](https://github.com/falcosecurity/plugins/commit/755ec40b) update(plugins/container): bump to 0.3.6

* [`ffdf1e2`](https://github.com/falcosecurity/plugins/commit/ffdf1e22) fix(plugins/container): container_info to_json


## v0.3.5

* [`411f0f7`](https://github.com/falcosecurity/plugins/commit/411f0f73) fix(plugins/container): do not use async methods in scap replay mode (ie: whe...

* [`beabb1f`](https://github.com/falcosecurity/plugins/commit/beabb1f6) cleanup(plugins/container): always use `procexit` logic to cleanup containers...

* [`78247e7`](https://github.com/falcosecurity/plugins/commit/78247e76) new(plugins/container): properly send `container_removed` events for bpm,lxc,...


## v0.3.4

* [`885c18e`](https://github.com/falcosecurity/plugins/commit/885c18ef) update(plugins/container): bump to 0.3.4.

* [`11c7d16`](https://github.com/falcosecurity/plugins/commit/11c7d166) chore(plugins/container): move error log to debug level.

* [`0275c81`](https://github.com/falcosecurity/plugins/commit/0275c81b) chore(plugins/container): added some tests around workerLoop().

* [`4bcabb2`](https://github.com/falcosecurity/plugins/commit/4bcabb2e) chore(plugins/container): improve exit strategy for goroutine workers when st...

* [`dd90663`](https://github.com/falcosecurity/plugins/commit/dd90663b) chore(plugins/container): fixed a log.

* [`4684790`](https://github.com/falcosecurity/plugins/commit/46847907) fix(plugins/container): fixed build under recent gcc by including `algorithm`.

* [`2487f7c`](https://github.com/falcosecurity/plugins/commit/2487f7c7) chore(plugins/container): move `containerEventsErrorTimeout` to cri.

* [`2fc5772`](https://github.com/falcosecurity/plugins/commit/2fc5772d) cleanup(plugins/container): podman `system.Events` now returns error synchron...

* [`f9da9fa`](https://github.com/falcosecurity/plugins/commit/f9da9fa4) chore(plugins/container): port docker engine away from deprecated APIs.

* [`7bb3847`](https://github.com/falcosecurity/plugins/commit/7bb3847f) Podman init will expose nil on the error channel if init was successful

* [`59ae99b`](https://github.com/falcosecurity/plugins/commit/59ae99b4) Optimize pull request - avoid unnecessary go routines and move constant defin...

* [`4a03991`](https://github.com/falcosecurity/plugins/commit/4a03991a) Update plugins/container/src/plugin.cpp

* [`b58dd18`](https://github.com/falcosecurity/plugins/commit/b58dd18c) Apply suggestions from code review

* [`d37f218`](https://github.com/falcosecurity/plugins/commit/d37f2183) Container plugin workaround fixing issues #3610 and #3630 for cri-o and podma...

* [`f4d1772`](https://github.com/falcosecurity/plugins/commit/f4d1772d) Container plugin workaround fixing cri-o issues #3610 and #3630


## v0.3.3

* [`5ca391e`](https://github.com/falcosecurity/plugins/commit/5ca391e7) update(plugins/container): bump to v0.3.3

* [`f28adb7`](https://github.com/falcosecurity/plugins/commit/f28adb7d) fix(plugins/container): parse_exit_process_event

* [`a97e226`](https://github.com/falcosecurity/plugins/commit/a97e2269) chore(container/make): add CMAKE_EXPORT_COMPILE_COMMANDS


## v0.3.2

* [`92ec4dc`](https://github.com/falcosecurity/plugins/commit/92ec4dcb) chore(plugins/container): add a trace log when removing container from procexit.

* [`6a75982`](https://github.com/falcosecurity/plugins/commit/6a759828) update(plugins/container): bump version to 0.3.2.

* [`1f8a375`](https://github.com/falcosecurity/plugins/commit/1f8a375a) fix(plugins/container): properly cleanup stale container cache entries for ex...

* [`2f4b632`](https://github.com/falcosecurity/plugins/commit/2f4b6327) chore(plugins/container): properly cleanup fetchCh in test.

* [`42fe4e2`](https://github.com/falcosecurity/plugins/commit/42fe4e2f) update(docs): updated container plugin readme.

* [`1c135e3`](https://github.com/falcosecurity/plugins/commit/1c135e36) chore(plugins/container): let async_ctx own the fetcher channel.

* [`d3305f8`](https://github.com/falcosecurity/plugins/commit/d3305f85) build(deps): bump github.com/containers/podman/v5

* [`6e02f91`](https://github.com/falcosecurity/plugins/commit/6e02f917) chore(plugins/container): drop fulfilled TODOs

* [`e8745cf`](https://github.com/falcosecurity/plugins/commit/e8745cf1) chore(plugins/container): introduce and use container_info::ptr_t

* [`db2b9c9`](https://github.com/falcosecurity/plugins/commit/db2b9c9c) chore(plugins/container): headers cleanup

* [`a7da58c`](https://github.com/falcosecurity/plugins/commit/a7da58ce) chore(plugins/container): avoid building unneeded RE-flex targets

* [`e281227`](https://github.com/falcosecurity/plugins/commit/e281227c) fix(container): detect libpod container ids with cgroups mode split


## v0.3.1

* [`398db32`](https://github.com/falcosecurity/plugins/commit/398db329) new(plugins/container): add test around null healthcheck in container json.

* [`ab266f5`](https://github.com/falcosecurity/plugins/commit/ab266f50) fix(plugins/container): fix healthcheck probe args retrieval since they can b...


## v0.3.0

* [`2b5f8a8`](https://github.com/falcosecurity/plugins/commit/2b5f8a8f) update(plugins/container): bump plugin version to 0.3.0

* [`5cfa378`](https://github.com/falcosecurity/plugins/commit/5cfa3780) chore(plugins/container): set an unexisted tid on generated asyncevents.


## v0.2.6

* [`f01e70d`](https://github.com/falcosecurity/plugins/commit/f01e70d6) update(plugins/container): bump container plugin to 0.2.6.

* [`5fcee14`](https://github.com/falcosecurity/plugins/commit/5fcee14c) fix(plugins/container): avoid possible nil ptr dereference in cri and contain...


## v0.2.5

* [`2bb872e`](https://github.com/falcosecurity/plugins/commit/2bb872ee) fx(plugins/container): do not override containers_image_openpgp tag in `exe` ...

* [`1fe9569`](https://github.com/falcosecurity/plugins/commit/1fe9569c) chore(ci,plugins/container): use `-tags containers_image_openpgp ` for test m...

* [`576b1c9`](https://github.com/falcosecurity/plugins/commit/576b1c9f) fix(plugins/container): redefine port binding port and IP as integers


## v0.2.4

* [`b1a5800`](https://github.com/falcosecurity/plugins/commit/b1a5800b) chore(plugins/container): bump version to 0.2.4

* [`4792bca`](https://github.com/falcosecurity/plugins/commit/4792bca6) build(deps): bump github.com/containerd/containerd/v2


## v0.2.3

* [`c64a5c8`](https://github.com/falcosecurity/plugins/commit/c64a5c84) chore(docs): updated plugin container readme.

* [`74b643a`](https://github.com/falcosecurity/plugins/commit/74b643ad) chore(src): fix formatting.

* [`bc645a8`](https://github.com/falcosecurity/plugins/commit/bc645a81) docs(plugins/container): deprecation message for old `k8s` fields

* [`298b671`](https://github.com/falcosecurity/plugins/commit/298b671a) chore(plugins/container): avoid useless req.set_value of empty string.


## v0.2.2

* [`9c1c488`](https://github.com/falcosecurity/plugins/commit/9c1c4880) fix(plugins/container): use `C.GoString()` in `AskForContainerInfo`.

* [`b909298`](https://github.com/falcosecurity/plugins/commit/b9092985) update(plugins/container): bumped plugin container to 0.2.2.

* [`a5840d1`](https://github.com/falcosecurity/plugins/commit/a5840d16) fix(plugins/container): use an unique ctx for fetcher.


## v0.2.1

* [`7fef864`](https://github.com/falcosecurity/plugins/commit/7fef864e) new(plugins/container): suggest more output fields.

* [`b8140c8`](https://github.com/falcosecurity/plugins/commit/b8140c8a) chore(plugins/container): bump version to 0.2.1.

* [`c122ed4`](https://github.com/falcosecurity/plugins/commit/c122ed40) chore(plugins/container): make ASYNC cap resilient to multiple calls.

* [`e25a1f8`](https://github.com/falcosecurity/plugins/commit/e25a1f8a) cleanup(plugins/container): drop `async_ctx` static variable.


## v0.2.0

* [`ea11491`](https://github.com/falcosecurity/plugins/commit/ea114916) build(deps): bump golang.org/x/net in /plugins/container/go-worker

* [`0d595a2`](https://github.com/falcosecurity/plugins/commit/0d595a22) new(plugins/container): added fetcher tests.

* [`89712a5`](https://github.com/falcosecurity/plugins/commit/89712a55) fix(plugin/container): avoid overwriting host container info when loading pre...

* [`ff332cb`](https://github.com/falcosecurity/plugins/commit/ff332cb3) fix(plugins/container): fixed CRI listing filter.

* [`5b374f7`](https://github.com/falcosecurity/plugins/commit/5b374f75) new(plugins/container): immediately enrich plugin cache with pre-existing con...

* [`ca2c560`](https://github.com/falcosecurity/plugins/commit/ca2c5606) new(plugins/container): print a debug log with all connected engine sockets.

* [`37fdf54`](https://github.com/falcosecurity/plugins/commit/37fdf54e) cleanup(plugins/container/go-worker): dropped inotifier support.

* [`d6e6c6e`](https://github.com/falcosecurity/plugins/commit/d6e6c6ee) chore(plugins/container): broaden exceptions management.

* [`e318e18`](https://github.com/falcosecurity/plugins/commit/e318e182) chore(plugins/container): bump container plugin to 0.2.0.

* [`d81c8c5`](https://github.com/falcosecurity/plugins/commit/d81c8c50) fix(plugins/container): fixed config tests.

* [`911e33d`](https://github.com/falcosecurity/plugins/commit/911e33d8) chore(plugins/container): updated readme.

* [`adec84a`](https://github.com/falcosecurity/plugins/commit/adec84aa) new(plugins/container): allow to specify which hook to be attached between {"...

* [`7c7cb4b`](https://github.com/falcosecurity/plugins/commit/7c7cb4bd) build(deps): bump github.com/containerd/containerd/v2


## v0.1.0

* [`103b5b2`](https://github.com/falcosecurity/plugins/commit/103b5b23) update(build,plugins): bump plugin-sdk-go to 0.7.5.

* [`d8a42ad`](https://github.com/falcosecurity/plugins/commit/d8a42ad5) chore(docs): updated container plugin readme through readme tool.

* [`9a6f285`](https://github.com/falcosecurity/plugins/commit/9a6f285c) new(plugins): initial import of container plugin.


