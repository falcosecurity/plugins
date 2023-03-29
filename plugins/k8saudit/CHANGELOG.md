# Changelog

## v0.5.0

* [`9e623ef`](https://github.com/falcosecurity/plugins/commit/9e623ef) update(plugins/k8saudit): bump plugin version to v0.5.0

* [`a2989d1`](https://github.com/falcosecurity/plugins/commit/a2989d1) fix(plugin/k8saudit): Add missing comma

* [`9a5d083`](https://github.com/falcosecurity/plugins/commit/9a5d083) update(rules/k8saudit): bump required_plugins_versions for k8saudit rules

* [`0809a56`](https://github.com/falcosecurity/plugins/commit/0809a56) fix(plugins/k8saudit): prevent panics while shutting down webserver


## v0.4.1

* [`f4dcac2`](https://github.com/falcosecurity/plugins/commit/f4dcac2) update(plugins/k8saudit): bump version to 0.4.1 for patched ruleset

* [`c83fb72`](https://github.com/falcosecurity/plugins/commit/c83fb72) update(plugins/k8saudit): update ruleset to support k8saudit-eks alternative ...


## v0.4.0

* [`f4315ff`](https://github.com/falcosecurity/plugins/commit/f4315ff) update(plugins/k8saudit): bump plugin version to v0.4.0

* [`256c669`](https://github.com/falcosecurity/plugins/commit/256c669) docs(k8saudit): update README.md

* [`3ff5e94`](https://github.com/falcosecurity/plugins/commit/3ff5e94) update(plugins/k8saudit): bumo plugin version to 0.4.0-rc1

* [`84f3061`](https://github.com/falcosecurity/plugins/commit/84f3061) feature(plugins/k8saudit/rules): Add ka.target.resource to each rule as defau...

* [`f90c4f6`](https://github.com/falcosecurity/plugins/commit/f90c4f6) update(plugins/k8saudit): fix makefile cleanup


## v0.3.0

* [`df79bbf`](https://github.com/falcosecurity/plugins/commit/df79bbf) update(plugins/k8saudit): bump version to 0.3.0

* [`37ca72b`](https://github.com/falcosecurity/plugins/commit/37ca72b) refactor(plugins/k8saudit): implement k8saudit event source using prebuilts f...


## v0.2.1

* [`6c920da`](https://github.com/falcosecurity/plugins/commit/6c920da) update(plugins/k8saudit): bump plugin version to 0.2.1

* [`a9b4988`](https://github.com/falcosecurity/plugins/commit/a9b4988) fix(plugins/k8saudit): return non-nil error from NextBatch with closed channel


## v0.2.0

* [`a30cfaa`](https://github.com/falcosecurity/plugins/commit/a30cfaa) update(plugins/k8saudit): adapt plugin for plugin-sdk-go v0.4.0

* [`4257d88`](https://github.com/falcosecurity/plugins/commit/4257d88) update(plugins/k8saudit): add new config entries to readme

* [`9384788`](https://github.com/falcosecurity/plugins/commit/9384788) update(plugins/k8saudit): adapt plugin for plugin-sdk-go v0.4.0

* [`43b7eb6`](https://github.com/falcosecurity/plugins/commit/43b7eb6) fix(plugins/k8saudit): drop events larger than max evt size

* [`b4b22f1`](https://github.com/falcosecurity/plugins/commit/b4b22f1) refactor(plugins/k8saudit): make evt size and batch size configurable with of...

* [`91cc17b`](https://github.com/falcosecurity/plugins/commit/91cc17b) refactor(plugins/k8saudit): bump sdk go version

* [`5fc7655`](https://github.com/falcosecurity/plugins/commit/5fc7655) chore(plugins/k8saudit): update maxEventBytes default value

* [`eb3e49d`](https://github.com/falcosecurity/plugins/commit/eb3e49d) chore(plugins/k8saudit): use logging for bad requests

* [`972ac41`](https://github.com/falcosecurity/plugins/commit/972ac41) fix(plugins/k8saudit): correctly parse and respond for http requests

* [`bf0cce1`](https://github.com/falcosecurity/plugins/commit/bf0cce1) fix(plugins/k8saudit): make corrupted jsons non-blocking

* [`fc2a956`](https://github.com/falcosecurity/plugins/commit/fc2a956) new(plugins/k8saudit): add internal plugin logger

* [`177b232`](https://github.com/falcosecurity/plugins/commit/177b232) chore(plugins/k8saudit): export plugin config field

* [`122bed3`](https://github.com/falcosecurity/plugins/commit/122bed3) new(plugins/k8saudit): make async extraction part of init config


## v0.1.0

* [`12a4c24`](https://github.com/falcosecurity/plugins/commit/12a4c24) refactor(plugins/k8saudit): properly handle open params prefix

* [`921535f`](https://github.com/falcosecurity/plugins/commit/921535f) fix(plugins/k8saudit): fix webserver host resolution

* [`ea894aa`](https://github.com/falcosecurity/plugins/commit/ea894aa) docs(plugins/k8saudit): add readme

* [`1084e52`](https://github.com/falcosecurity/plugins/commit/1084e52) fix(plugins/k8saudit): fix extraction of ka.req.pod.volumes.volume_type

* [`b0a7177`](https://github.com/falcosecurity/plugins/commit/b0a7177) update(plugins/k8saudit): change default config values

* [`a55436f`](https://github.com/falcosecurity/plugins/commit/a55436f) update(plugins/k8saudit): open filepath by default if prefix is unknown

* [`7386f82`](https://github.com/falcosecurity/plugins/commit/7386f82) refactor(plugins/k8saudit): create package directory

* [`bf61ca8`](https://github.com/falcosecurity/plugins/commit/bf61ca8) chore(k8saudit): move ruleset to plugin folder

* [`d2cfa30`](https://github.com/falcosecurity/plugins/commit/d2cfa30) refactor(plugins/k8saudit): do not return <NA> on missing field values

* [`e2ad7d1`](https://github.com/falcosecurity/plugins/commit/e2ad7d1) refactor(plugins/k8saudit): allow non-blocking null values and place <NA> lik...

* [`e759462`](https://github.com/falcosecurity/plugins/commit/e759462) refactor(plugins/k8saudit): implement recursive json exploration and simplify...

* [`d8f9194`](https://github.com/falcosecurity/plugins/commit/d8f9194) refactor(plugins/k8saudit): remove unused u64 extraction logic

* [`16a1955`](https://github.com/falcosecurity/plugins/commit/16a1955) test(plugins/k8saudit): add k8saudit extractor rough benchmark

* [`d709cd5`](https://github.com/falcosecurity/plugins/commit/d709cd5) fix(plugins/k8saudit): fix typo that caused null ptr error

* [`f205356`](https://github.com/falcosecurity/plugins/commit/f205356) update(plugins/k8saudit): reject unrelated JSON from extraction and add webse...

* [`5e9826c`](https://github.com/falcosecurity/plugins/commit/5e9826c) refactor(plugins/k8saudit): use a default event timeout

* [`41effdd`](https://github.com/falcosecurity/plugins/commit/41effdd) refactor(plugins/k8saudit): bump plugin sdk go version and adapt field arg de...

* [`b93d09e`](https://github.com/falcosecurity/plugins/commit/b93d09e) update(plugins/k8saudit): improve error handling and resource disposal

* [`059e0d0`](https://github.com/falcosecurity/plugins/commit/059e0d0) new(plugins/k8saudit): initial implementation of K8S audit plugin


