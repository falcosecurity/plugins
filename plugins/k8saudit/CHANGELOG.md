# Changelog

## v0.13.0

* [`f9d1eef`](https://github.com/falcosecurity/plugins/commit/f9d1eef7) chore(plugins/k8saudit): bump to v0.13.0

## v0.12.0

* [`1da1fc0`](https://github.com/falcosecurity/plugins/commit/1da1fc0d) update(plugins/k8saudit): bump to v0.12.0

* [`e5a4c20`](https://github.com/falcosecurity/plugins/commit/e5a4c209) update(plugins/k8saudit): update `required_plugin_versions` in ruleset

* [`a383f07`](https://github.com/falcosecurity/plugins/commit/a383f07d) new(plugins/k8saudit): add subject name fields


## v0.11.0

* [`45e716e`](https://github.com/falcosecurity/plugins/commit/45e716e8) update(k8saudit): bump to v0.11


## v0.10.1

* [`56e3a81`](https://github.com/falcosecurity/plugins/commit/56e3a810) update(plugins/k8saudit): upgrade sdk and deps


## v0.10.0-rc1


## v0.10.0

* [`5e23552`](https://github.com/falcosecurity/plugins/commit/5e235527) chore(plugins/k8saudit): use rc tag

* [`ab63a13`](https://github.com/falcosecurity/plugins/commit/ab63a13b) feat(plugins/k8saudit): extract pod name

* [`31c2f53`](https://github.com/falcosecurity/plugins/commit/31c2f535) feat(plugins/k8saudit): extract cluster name


## v0.9.0

* [`42fcdae`](https://github.com/falcosecurity/plugins/commit/42fcdae9) chore(plugins/k8saudit): bump plugin version to 0.9.0

* [`472fd1f`](https://github.com/falcosecurity/plugins/commit/472fd1fc) fix(plugins/k8saudit/rules): split rbac rules by individual rbac object


## v0.8.0

* [`4a3da48`](https://github.com/falcosecurity/plugins/commit/4a3da484) chore(k8saudit): bump version to 0.8.0 to release rule changes

* [`24e9f22`](https://github.com/falcosecurity/plugins/commit/24e9f229) update(plugins/k8s_audit): rename more falco_ lists

* [`0879a81`](https://github.com/falcosecurity/plugins/commit/0879a813) update(plugins/k8s_audit): k8s_* -> k8s_audit_*

* [`2c4a275`](https://github.com/falcosecurity/plugins/commit/2c4a2757) cleanup(plugins/k8s_audit): make the rulesefile self-referenced

* [`ef07168`](https://github.com/falcosecurity/plugins/commit/ef071688) chore(k8saudit): add k8saudit-gke as plugin alternative

* [`0c21c8a`](https://github.com/falcosecurity/plugins/commit/0c21c8a5) update(k8saudit/docs): add k8s configuration files


## v0.7.0


## v0.6.1


## v0.6.0

* [`0c6922e`](https://github.com/falcosecurity/plugins/commit/0c6922e3) feat(plugins/k8saudit): include query params in health check endpoint exceptions


## v0.5.3

* [`8949655`](https://github.com/falcosecurity/plugins/commit/89496553) fix(plugins/k8saudit): fix dependencies in ruleset


## v0.5.2


## v0.5.1

* [`8ce5b5b`](https://github.com/falcosecurity/plugins/commit/8ce5b5b3) feature(plugins/k8saudit/rules): Add two additional users to eks_allowed_k8s_...


## v0.5.0

* [`9e623ef`](https://github.com/falcosecurity/plugins/commit/9e623ef4) update(plugins/k8saudit): bump plugin version to v0.5.0

* [`a2989d1`](https://github.com/falcosecurity/plugins/commit/a2989d11) fix(plugin/k8saudit): Add missing comma

* [`9a5d083`](https://github.com/falcosecurity/plugins/commit/9a5d0833) update(rules/k8saudit): bump required_plugins_versions for k8saudit rules

* [`0809a56`](https://github.com/falcosecurity/plugins/commit/0809a56b) fix(plugins/k8saudit): prevent panics while shutting down webserver


## v0.4.1

* [`f4dcac2`](https://github.com/falcosecurity/plugins/commit/f4dcac29) update(plugins/k8saudit): bump version to 0.4.1 for patched ruleset

* [`c83fb72`](https://github.com/falcosecurity/plugins/commit/c83fb72b) update(plugins/k8saudit): update ruleset to support k8saudit-eks alternative ...


## v0.4.0

* [`f4315ff`](https://github.com/falcosecurity/plugins/commit/f4315ffa) update(plugins/k8saudit): bump plugin version to v0.4.0

* [`256c669`](https://github.com/falcosecurity/plugins/commit/256c669e) docs(k8saudit): update README.md

* [`3ff5e94`](https://github.com/falcosecurity/plugins/commit/3ff5e94c) update(plugins/k8saudit): bumo plugin version to 0.4.0-rc1

* [`84f3061`](https://github.com/falcosecurity/plugins/commit/84f30619) feature(plugins/k8saudit/rules): Add ka.target.resource to each rule as defau...

* [`f90c4f6`](https://github.com/falcosecurity/plugins/commit/f90c4f68) update(plugins/k8saudit): fix makefile cleanup


## v0.3.0

* [`df79bbf`](https://github.com/falcosecurity/plugins/commit/df79bbf9) update(plugins/k8saudit): bump version to 0.3.0

* [`37ca72b`](https://github.com/falcosecurity/plugins/commit/37ca72ba) refactor(plugins/k8saudit): implement k8saudit event source using prebuilts f...


## v0.2.1

* [`6c920da`](https://github.com/falcosecurity/plugins/commit/6c920da5) update(plugins/k8saudit): bump plugin version to 0.2.1

* [`a9b4988`](https://github.com/falcosecurity/plugins/commit/a9b4988d) fix(plugins/k8saudit): return non-nil error from NextBatch with closed channel


## v0.2.0

* [`a30cfaa`](https://github.com/falcosecurity/plugins/commit/a30cfaaa) update(plugins/k8saudit): adapt plugin for plugin-sdk-go v0.4.0

* [`4257d88`](https://github.com/falcosecurity/plugins/commit/4257d88d) update(plugins/k8saudit): add new config entries to readme

* [`9384788`](https://github.com/falcosecurity/plugins/commit/93847884) update(plugins/k8saudit): adapt plugin for plugin-sdk-go v0.4.0

* [`43b7eb6`](https://github.com/falcosecurity/plugins/commit/43b7eb6a) fix(plugins/k8saudit): drop events larger than max evt size

* [`b4b22f1`](https://github.com/falcosecurity/plugins/commit/b4b22f13) refactor(plugins/k8saudit): make evt size and batch size configurable with of...

* [`91cc17b`](https://github.com/falcosecurity/plugins/commit/91cc17b4) refactor(plugins/k8saudit): bump sdk go version

* [`5fc7655`](https://github.com/falcosecurity/plugins/commit/5fc76555) chore(plugins/k8saudit): update maxEventBytes default value

* [`eb3e49d`](https://github.com/falcosecurity/plugins/commit/eb3e49d9) chore(plugins/k8saudit): use logging for bad requests

* [`972ac41`](https://github.com/falcosecurity/plugins/commit/972ac410) fix(plugins/k8saudit): correctly parse and respond for http requests

* [`bf0cce1`](https://github.com/falcosecurity/plugins/commit/bf0cce10) fix(plugins/k8saudit): make corrupted jsons non-blocking

* [`fc2a956`](https://github.com/falcosecurity/plugins/commit/fc2a956d) new(plugins/k8saudit): add internal plugin logger

* [`177b232`](https://github.com/falcosecurity/plugins/commit/177b2328) chore(plugins/k8saudit): export plugin config field

* [`122bed3`](https://github.com/falcosecurity/plugins/commit/122bed39) new(plugins/k8saudit): make async extraction part of init config


## v0.1.0

* [`12a4c24`](https://github.com/falcosecurity/plugins/commit/12a4c246) refactor(plugins/k8saudit): properly handle open params prefix

* [`921535f`](https://github.com/falcosecurity/plugins/commit/921535fd) fix(plugins/k8saudit): fix webserver host resolution

* [`ea894aa`](https://github.com/falcosecurity/plugins/commit/ea894aa3) docs(plugins/k8saudit): add readme

* [`1084e52`](https://github.com/falcosecurity/plugins/commit/1084e528) fix(plugins/k8saudit): fix extraction of ka.req.pod.volumes.volume_type

* [`b0a7177`](https://github.com/falcosecurity/plugins/commit/b0a71778) update(plugins/k8saudit): change default config values

* [`a55436f`](https://github.com/falcosecurity/plugins/commit/a55436f3) update(plugins/k8saudit): open filepath by default if prefix is unknown

* [`7386f82`](https://github.com/falcosecurity/plugins/commit/7386f825) refactor(plugins/k8saudit): create package directory

* [`bf61ca8`](https://github.com/falcosecurity/plugins/commit/bf61ca87) chore(k8saudit): move ruleset to plugin folder

* [`5af2b92`](https://github.com/falcosecurity/plugins/commit/5af2b922) new(rules/k8s_audit): add rules to detect pods sharing host pid and IPC names...

* [`d2cfa30`](https://github.com/falcosecurity/plugins/commit/d2cfa302) refactor(plugins/k8saudit): do not return <NA> on missing field values

* [`e2ad7d1`](https://github.com/falcosecurity/plugins/commit/e2ad7d11) refactor(plugins/k8saudit): allow non-blocking null values and place <NA> lik...

* [`e759462`](https://github.com/falcosecurity/plugins/commit/e759462c) refactor(plugins/k8saudit): implement recursive json exploration and simplify...

* [`d8f9194`](https://github.com/falcosecurity/plugins/commit/d8f91944) refactor(plugins/k8saudit): remove unused u64 extraction logic

* [`16a1955`](https://github.com/falcosecurity/plugins/commit/16a1955f) test(plugins/k8saudit): add k8saudit extractor rough benchmark

* [`d709cd5`](https://github.com/falcosecurity/plugins/commit/d709cd5d) fix(plugins/k8saudit): fix typo that caused null ptr error

* [`f205356`](https://github.com/falcosecurity/plugins/commit/f205356a) update(plugins/k8saudit): reject unrelated JSON from extraction and add webse...

* [`5e9826c`](https://github.com/falcosecurity/plugins/commit/5e9826c9) refactor(plugins/k8saudit): use a default event timeout

* [`41effdd`](https://github.com/falcosecurity/plugins/commit/41effdd6) refactor(plugins/k8saudit): bump plugin sdk go version and adapt field arg de...

* [`b93d09e`](https://github.com/falcosecurity/plugins/commit/b93d09e3) update(plugins/k8saudit): improve error handling and resource disposal

* [`059e0d0`](https://github.com/falcosecurity/plugins/commit/059e0d0d) new(plugins/k8saudit): initial implementation of K8S audit plugin


