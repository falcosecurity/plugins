# Changelog

## v0.16.1

* [`3b08092`](https://github.com/falcosecurity/plugins/commit/3b08092) chore(plugins/k8saudit): bump to v0.16.1

* [`3a2616d`](https://github.com/falcosecurity/plugins/commit/3a2616d) fix(plugins/k8saudit): handle fastjson panic on large payloads

## v0.16.0

* [`8b1d3e2`](https://github.com/falcosecurity/plugins/commit/8b1d3e2) update(plugins/k8saudit): bump to v0.16.0

* [`3916d85`](https://github.com/falcosecurity/plugins/commit/3916d85) chore(plugins): bulk update to plugin-sdk-go to v0.8.3

* [`e8d9031`](https://github.com/falcosecurity/plugins/commit/e8d9031) build(deps): bump the gomod group across 13 directories with 7 updates

* [`f05c6c4`](https://github.com/falcosecurity/plugins/commit/f05c6c4) update(k8saudit): Add support for field offsets

* [`ebf9702`](https://github.com/falcosecurity/plugins/commit/ebf9702) docs(plugins/k8saudit): improve README.md


## v0.15.0

* [`65cb078`](https://github.com/falcosecurity/plugins/commit/65cb078) fix(extract.go): renaming variables to match context

* [`3fcea87`](https://github.com/falcosecurity/plugins/commit/3fcea87) new(k8saudit): add extraction of container command and args from pods


## v0.14.0

* [`db8f412`](https://github.com/falcosecurity/plugins/commit/db8f412) chore(k8saudit): update readme with new field

* [`03b1df3`](https://github.com/falcosecurity/plugins/commit/03b1df3) update(k8saudit): bump version to 0.14.0

* [`59af3f9`](https://github.com/falcosecurity/plugins/commit/59af3f9) new(k8saudit): add field for extracting container names from pods

* [`319bdd4`](https://github.com/falcosecurity/plugins/commit/319bdd4) able to get pod security policy violations from audit events

* [`e3e4d0c`](https://github.com/falcosecurity/plugins/commit/e3e4d0c) docs(plugins/k8saudit): update README


## v0.13.0

* [`f046209`](https://github.com/falcosecurity/plugins/commit/f046209) update(plugins/k8saudit): bump to v0.13.0

* [`4b6e9f3`](https://github.com/falcosecurity/plugins/commit/4b6e9f3) able to get validation failure message from a Validating admission policy

* [`103b5b2`](https://github.com/falcosecurity/plugins/commit/103b5b2) update(build,plugins): bump plugin-sdk-go to 0.7.5.

* [`8094fa3`](https://github.com/falcosecurity/plugins/commit/8094fa3) chore(plugins): bulk go mod tidy


## v0.12.0

* [`1da1fc0`](https://github.com/falcosecurity/plugins/commit/1da1fc0) update(plugins/k8saudit): bump to v0.12.0

* [`e5a4c20`](https://github.com/falcosecurity/plugins/commit/e5a4c20) update(plugins/k8saudit): update `required_plugin_versions` in ruleset

* [`42e49c7`](https://github.com/falcosecurity/plugins/commit/42e49c7) fix the rule to detect the exec in EKS

* [`453dd87`](https://github.com/falcosecurity/plugins/commit/453dd87) Add k8saudit-ovh plugin

* [`a383f07`](https://github.com/falcosecurity/plugins/commit/a383f07) new(plugins/k8saudit): add subject name fields


## v0.11.0

* [`45e716e`](https://github.com/falcosecurity/plugins/commit/45e716e) update(k8saudit): bump to v0.11

* [`cea7600`](https://github.com/falcosecurity/plugins/commit/cea7600) fix:Do not output information that contains confidential data.


## v0.10.1

* [`b31ad61`](https://github.com/falcosecurity/plugins/commit/b31ad61) docs(plugins): update README.md

* [`56e3a81`](https://github.com/falcosecurity/plugins/commit/56e3a81) update(plugins/k8saudit): upgrade sdk and deps

* [`aaee539`](https://github.com/falcosecurity/plugins/commit/aaee539) chore(plugins): bump versions


## v0.10.0-rc1


## v0.10.0

* [`aaee539`](https://github.com/falcosecurity/plugins/commit/aaee539) chore(plugins): bump versions

* [`5e23552`](https://github.com/falcosecurity/plugins/commit/5e23552) chore(plugins/k8saudit): use rc tag

* [`63b7093`](https://github.com/falcosecurity/plugins/commit/63b7093) chore(plugin/cloudtrail): bump cloudtrail version to 0.10.0

* [`e66527d`](https://github.com/falcosecurity/plugins/commit/e66527d) add field info fields list

* [`ab63a13`](https://github.com/falcosecurity/plugins/commit/ab63a13) feat(plugins/k8saudit): extract pod name

* [`1a559ef`](https://github.com/falcosecurity/plugins/commit/1a559ef) apply feedback; add field into fields.go

* [`31c2f53`](https://github.com/falcosecurity/plugins/commit/31c2f53) feat(plugins/k8saudit): extract cluster name

* [`65aed62`](https://github.com/falcosecurity/plugins/commit/65aed62) Add ka.auth.openshift.decision and ka.auth.openshift.username as fields to al...


## v0.9.0

* [`42fcdae`](https://github.com/falcosecurity/plugins/commit/42fcdae) chore(plugins/k8saudit): bump plugin version to 0.9.0

* [`472fd1f`](https://github.com/falcosecurity/plugins/commit/472fd1f) fix(plugins/k8saudit/rules): split rbac rules by individual rbac object


## v0.8.0

* [`4a3da48`](https://github.com/falcosecurity/plugins/commit/4a3da48) chore(k8saudit): bump version to 0.8.0 to release rule changes

* [`24e9f22`](https://github.com/falcosecurity/plugins/commit/24e9f22) update(plugins/k8s_audit): rename more falco_ lists

* [`0879a81`](https://github.com/falcosecurity/plugins/commit/0879a81) update(plugins/k8s_audit): k8s_* -> k8s_audit_*

* [`2f2e624`](https://github.com/falcosecurity/plugins/commit/2f2e624) update(rules): remove references to k8s.io

* [`2c4a275`](https://github.com/falcosecurity/plugins/commit/2c4a275) cleanup(plugins/k8s_audit): make the rulesefile self-referenced

* [`ef07168`](https://github.com/falcosecurity/plugins/commit/ef07168) chore(k8saudit): add k8saudit-gke as plugin alternative

* [`0c21c8a`](https://github.com/falcosecurity/plugins/commit/0c21c8a) update(k8saudit/docs): add k8s configuration files


## v0.7.0

* [`091c6bb`](https://github.com/falcosecurity/plugins/commit/091c6bb) update(plugins): k8saudit-0.7.0

* [`028fa19`](https://github.com/falcosecurity/plugins/commit/028fa19) feat(plugins/k8saudit/rules) add detection for portforwarding

* [`34ab875`](https://github.com/falcosecurity/plugins/commit/34ab875) docs: add SPDX license identifier


## v0.6.1

* [`69618af`](https://github.com/falcosecurity/plugins/commit/69618af) update(plugins): bump to-be-released plugin versions.

* [`14ae3c9`](https://github.com/falcosecurity/plugins/commit/14ae3c9) build: bump plugin-sdk-go to v0.7.3

* [`440c234`](https://github.com/falcosecurity/plugins/commit/440c234) fix(plugins): adopt cgocheck=1 in debug mode

* [`cced306`](https://github.com/falcosecurity/plugins/commit/cced306) chore(plugins): trigger sample CI checks


## v0.6.0

* [`81ffddd`](https://github.com/falcosecurity/plugins/commit/81ffddd) update(plugins): bump to-be-released plugin versions

* [`9166d80`](https://github.com/falcosecurity/plugins/commit/9166d80) update(plugins): bump plugin-go-sdk to v0.7.1

* [`de77005`](https://github.com/falcosecurity/plugins/commit/de77005) update(plugins): re-bump sdk go to latest dev version

* [`bec2147`](https://github.com/falcosecurity/plugins/commit/bec2147) update(plugins): bump sdk go to latest dev version

* [`0c6922e`](https://github.com/falcosecurity/plugins/commit/0c6922e) feat(plugins/k8saudit): include query params in health check endpoint exceptions


## v0.5.3

* [`8949655`](https://github.com/falcosecurity/plugins/commit/8949655) fix(plugins/k8saudit): fix dependencies in ruleset


## v0.5.2

* [`79d6f67`](https://github.com/falcosecurity/plugins/commit/79d6f67) update(plugin-versions): bump plugins and rules versions


## v0.5.1

* [`6e35f16`](https://github.com/falcosecurity/plugins/commit/6e35f16) update(plugins): bump plugins versions

* [`8ddaea1`](https://github.com/falcosecurity/plugins/commit/8ddaea1) update(plugins): bump plugin-sdk-go to v0.6.2

* [`03daaf8`](https://github.com/falcosecurity/plugins/commit/03daaf8) update k8s registry domain

* [`f5ebfb2`](https://github.com/falcosecurity/plugins/commit/f5ebfb2) chore: Add eks:addon-manager as well

* [`8ce5b5b`](https://github.com/falcosecurity/plugins/commit/8ce5b5b) feature(plugins/k8saudit/rules): Add two additional users to eks_allowed_k8s_...


## v0.5.0

* [`9e623ef`](https://github.com/falcosecurity/plugins/commit/9e623ef) update(plugins/k8saudit): bump plugin version to v0.5.0

* [`a2989d1`](https://github.com/falcosecurity/plugins/commit/a2989d1) fix(plugin/k8saudit): Add missing comma

* [`9a5d083`](https://github.com/falcosecurity/plugins/commit/9a5d083) update(rules/k8saudit): bump required_plugins_versions for k8saudit rules

* [`0809a56`](https://github.com/falcosecurity/plugins/commit/0809a56) fix(plugins/k8saudit): prevent panics while shutting down webserver

* [`e306efb`](https://github.com/falcosecurity/plugins/commit/e306efb) Apply suggestions from code review

* [`a818875`](https://github.com/falcosecurity/plugins/commit/a818875) added the sort standard library and fixed the results slice to use an io.Read...

* [`02ad670`](https://github.com/falcosecurity/plugins/commit/02ad670) changes after feedback

* [`c339cc2`](https://github.com/falcosecurity/plugins/commit/c339cc2) fixed the single file logic

* [`337246a`](https://github.com/falcosecurity/plugins/commit/337246a) added custom struct and io.MultiReader

* [`cdd7821`](https://github.com/falcosecurity/plugins/commit/cdd7821) pruned unnecessary code

* [`a47f56a`](https://github.com/falcosecurity/plugins/commit/a47f56a) forgot to add the filepath package

* [`5fdfe6b`](https://github.com/falcosecurity/plugins/commit/5fdfe6b) trim + construct the filepath and open before passing to the event stream

* [`27982f3`](https://github.com/falcosecurity/plugins/commit/27982f3) differentiate between single file and directory


## v0.4.1

* [`f4dcac2`](https://github.com/falcosecurity/plugins/commit/f4dcac2) update(plugins/k8saudit): bump version to 0.4.1 for patched ruleset

* [`c83fb72`](https://github.com/falcosecurity/plugins/commit/c83fb72) update(plugins/k8saudit): update ruleset to support k8saudit-eks alternative ...


## v0.4.0

* [`f4315ff`](https://github.com/falcosecurity/plugins/commit/f4315ff) update(plugins/k8saudit): bump plugin version to v0.4.0

* [`028b3bd`](https://github.com/falcosecurity/plugins/commit/028b3bd) update(plugins): bump plugin-sdk-go to v0.6.0

* [`256c669`](https://github.com/falcosecurity/plugins/commit/256c669) docs(k8saudit): update README.md

* [`41cd0f0`](https://github.com/falcosecurity/plugins/commit/41cd0f0) add containerd.sock to sensitive_vol_mount

* [`8efcec3`](https://github.com/falcosecurity/plugins/commit/8efcec3) add ka.sourceips

* [`3ff5e94`](https://github.com/falcosecurity/plugins/commit/3ff5e94) update(plugins/k8saudit): bumo plugin version to 0.4.0-rc1

* [`a0fd4d5`](https://github.com/falcosecurity/plugins/commit/a0fd4d5) chore: bump plugin-sdk-go v0.6.0-rc2 (plugin API v2)

* [`84f3061`](https://github.com/falcosecurity/plugins/commit/84f3061) feature(plugins/k8saudit/rules): Add ka.target.resource to each rule as defau...

* [`4b1872c`](https://github.com/falcosecurity/plugins/commit/4b1872c) update(plugins): generate rea

* [`6c9fd11`](https://github.com/falcosecurity/plugins/commit/6c9fd11) update(plugins): generate readmes

* [`550b3c3`](https://github.com/falcosecurity/plugins/commit/550b3c3) update(plugins): add readme entry in makefiles

* [`d142131`](https://github.com/falcosecurity/plugins/commit/d142131) update(plugins): add generator tags in readmes

* [`453d1ae`](https://github.com/falcosecurity/plugins/commit/453d1ae) update(plugins): Add titles and default values.

* [`f90c4f6`](https://github.com/falcosecurity/plugins/commit/f90c4f6) update(plugins/k8saudit): fix makefile cleanup


## v0.3.0

* [`df79bbf`](https://github.com/falcosecurity/plugins/commit/df79bbf) update(plugins/k8saudit): bump version to 0.3.0

* [`2606677`](https://github.com/falcosecurity/plugins/commit/2606677) update(plugins): upgrade go SDK to v0.5.0

* [`1bce4c1`](https://github.com/falcosecurity/plugins/commit/1bce4c1) fix(plugins): use right object for init schema reflection

* [`37ca72b`](https://github.com/falcosecurity/plugins/commit/37ca72b) refactor(plugins/k8saudit): implement k8saudit event source using prebuilts f...


## v0.2.1

* [`6c920da`](https://github.com/falcosecurity/plugins/commit/6c920da) update(plugins/k8saudit): bump plugin version to 0.2.1

* [`a9b4988`](https://github.com/falcosecurity/plugins/commit/a9b4988) fix(plugins/k8saudit): return non-nil error from NextBatch with closed channel


## v0.2.0

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

* [`52366d2`](https://github.com/falcosecurity/plugins/commit/52366d2) update(plugins): bump version requirements in plugin rulesets

* [`12a4c24`](https://github.com/falcosecurity/plugins/commit/12a4c24) refactor(plugins/k8saudit): properly handle open params prefix

* [`921535f`](https://github.com/falcosecurity/plugins/commit/921535f) fix(plugins/k8saudit): fix webserver host resolution

* [`ea894aa`](https://github.com/falcosecurity/plugins/commit/ea894aa) docs(plugins/k8saudit): add readme

* [`1084e52`](https://github.com/falcosecurity/plugins/commit/1084e52) fix(plugins/k8saudit): fix extraction of ka.req.pod.volumes.volume_type

* [`b0a7177`](https://github.com/falcosecurity/plugins/commit/b0a7177) update(plugins/k8saudit): change default config values

* [`a55436f`](https://github.com/falcosecurity/plugins/commit/a55436f) update(plugins/k8saudit): open filepath by default if prefix is unknown

* [`7386f82`](https://github.com/falcosecurity/plugins/commit/7386f82) refactor(plugins/k8saudit): create package directory

* [`f2ed025`](https://github.com/falcosecurity/plugins/commit/f2ed025) update(plugins): bump Go plugins deps and GO SDK to v0.3.0

* [`bf61ca8`](https://github.com/falcosecurity/plugins/commit/bf61ca8) chore(k8saudit): move ruleset to plugin folder

* [`440a4b3`](https://github.com/falcosecurity/plugins/commit/440a4b3) update(plugins): bump sdk version in go plugins

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


