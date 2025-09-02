# Changelog

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


## v0.3.3

* [`5ca391e`](https://github.com/falcosecurity/plugins/commit/5ca391e7) update(plugins/container): bump to v0.3.3

* [`f28adb7`](https://github.com/falcosecurity/plugins/commit/f28adb7d) fix(plugins/container): parse_exit_process_event

* [`a97e226`](https://github.com/falcosecurity/plugins/commit/a97e2269) chore(container/make): add CMAKE_EXPORT_COMPILE_COMMANDS


## v0.3.2

* [`92ec4dc`](https://github.com/falcosecurity/plugins/commit/92ec4dcb) chore(plugins/container): add a trace log when removing container from procexit.

* [`6a75982`](https://github.com/falcosecurity/plugins/commit/6a759828) update(plugins/container): bump version to 0.3.2.

* [`1f8a375`](https://github.com/falcosecurity/plugins/commit/1f8a375a) fix(plugins/container): properly cleanup stale container cache entries for ex...

* [`2f4b632`](https://github.com/falcosecurity/plugins/commit/2f4b6327) chore(plugins/container): properly cleanup fetchCh in test.

* [`1c135e3`](https://github.com/falcosecurity/plugins/commit/1c135e36) chore(plugins/container): let async_ctx own the fetcher channel.

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

* [`576b1c9`](https://github.com/falcosecurity/plugins/commit/576b1c9f) fix(plugins/container): redefine port binding port and IP as integers


## v0.2.4

* [`b1a5800`](https://github.com/falcosecurity/plugins/commit/b1a5800b) chore(plugins/container): bump version to 0.2.4


## v0.2.3

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

* [`0d595a2`](https://github.com/falcosecurity/plugins/commit/0d595a22) new(plugins/container): added fetcher tests.

* [`89712a5`](https://github.com/falcosecurity/plugins/commit/89712a55) fix(plugin/container): avoid overwriting host container info when loading pre...

* [`ff332cb`](https://github.com/falcosecurity/plugins/commit/ff332cb3) fix(plugins/container): fixed CRI listing filter.

* [`5b374f7`](https://github.com/falcosecurity/plugins/commit/5b374f75) new(plugins/container): immediately enrich plugin cache with pre-existing con...

* [`ca2c560`](https://github.com/falcosecurity/plugins/commit/ca2c5606) new(plugins/container): print a debug log with all connected engine sockets.

* [`d6e6c6e`](https://github.com/falcosecurity/plugins/commit/d6e6c6ee) chore(plugins/container): broaden exceptions management.

* [`e318e18`](https://github.com/falcosecurity/plugins/commit/e318e182) chore(plugins/container): bump container plugin to 0.2.0.

* [`d81c8c5`](https://github.com/falcosecurity/plugins/commit/d81c8c50) fix(plugins/container): fixed config tests.

* [`911e33d`](https://github.com/falcosecurity/plugins/commit/911e33d8) chore(plugins/container): updated readme.

* [`adec84a`](https://github.com/falcosecurity/plugins/commit/adec84aa) new(plugins/container): allow to specify which hook to be attached between {"...


## v0.1.0


