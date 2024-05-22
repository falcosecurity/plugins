# Changelog

## v0.12.2

* [`63b7093`](https://github.com/falcosecurity/plugins/commit/63b7093) chore(plugin/cloudtrail): bump cloudtrail version to 0.10.0


## v0.12.1

* [`c4ed2ca`](https://github.com/falcosecurity/plugins/commit/c4ed2ca) chore(plugins/cloudtrail): update changelog

* [`d775f53`](https://github.com/falcosecurity/plugins/commit/d775f53) chore(cloudtrail): replace moved package

* [`f43ca43`](https://github.com/falcosecurity/plugins/commit/f43ca43) chore(cloudtrail): update Go and dependencies


## v0.12.0

* [`b31948c`](https://github.com/falcosecurity/plugins/commit/b31948c) refactor(cloudtrail): Get S3 keys concurrently

* [`9920d35`](https://github.com/falcosecurity/plugins/commit/9920d35) feat(cloudtrail): support accounts for org trails

* [`746ea98`](https://github.com/falcosecurity/plugins/commit/746ea98) feat(cloudtrail): Support for organization trails

* [`9a1f86a`](https://github.com/falcosecurity/plugins/commit/9a1f86a) feat(cloudtrail): Add generic additionalEventData field

* [`0e4a687`](https://github.com/falcosecurity/plugins/commit/0e4a687) feat(cloudtrail): Add ct.response and ct.request field


## v0.11.0


## v0.10.0


## v0.9.1

* [`16306f2`](https://github.com/falcosecurity/plugins/commit/16306f2) update(cloudtrail): bump version to 0.9.1

* [`66c77be`](https://github.com/falcosecurity/plugins/commit/66c77be) fix(plugins/cloudtrail): remove wrong return statement when extracting recipi...


## v0.9.0

* [`3156ed5`](https://github.com/falcosecurity/plugins/commit/3156ed5) fix(plugins/cloudtrail): Generate the correct interval values

* [`5bbc310`](https://github.com/falcosecurity/plugins/commit/5bbc310) update(plugins/cloudtrail): Make our default interval ""

* [`431bcf8`](https://github.com/falcosecurity/plugins/commit/431bcf8) update(plugins/cloudtrail): Remove a dependency

* [`ef52d3c`](https://github.com/falcosecurity/plugins/commit/ef52d3c) update(plugins/cloudtrail): Fix a time comparison

* [`c02b076`](https://github.com/falcosecurity/plugins/commit/c02b076) update(plugins/cloudtrail): Add an S3Interval option

* [`4b1156b`](https://github.com/falcosecurity/plugins/commit/4b1156b) update(plugins/cloudtrail): Add dependencies to our Makefile

* [`9a0ec0d`](https://github.com/falcosecurity/plugins/commit/9a0ec0d) update(plugins/cloudtrail): Increase our default S3 concurrency


## v0.8.0

* [`9f36290`](https://github.com/falcosecurity/plugins/commit/9f36290) update(plugins/cloudtrail): Avoid duplicate event info


## v0.7.3

* [`3bac296`](https://github.com/falcosecurity/plugins/commit/3bac296) fix(plugins/cloudtrail): fix ruleset dependencies


## v0.7.2

* [`0c07efc`](https://github.com/falcosecurity/plugins/commit/0c07efc) feature(plugins/cloudtrail): add fields to plugin

* [`501f351`](https://github.com/falcosecurity/plugins/commit/501f351) fix(plugins/cloudtrail): if accountId not present in userIdentity, set it to ...


## v0.7.1


## v0.7.0

* [`3c6009b`](https://github.com/falcosecurity/plugins/commit/3c6009b) update(plugins/cloudtrail): bump plugin version to v0.7.0

* [`8984655`](https://github.com/falcosecurity/plugins/commit/8984655) update(rules/cloudtrail): bump required_plugins_versions for cloudtrail rules

* [`505a308`](https://github.com/falcosecurity/plugins/commit/505a308) update(plugins/cloudtrail): More friendly error messages


## v0.6.0

* [`0571948`](https://github.com/falcosecurity/plugins/commit/0571948) update(plugins/cloudtrail): bump plugin version to v0.6.0

* [`1db4264`](https://github.com/falcosecurity/plugins/commit/1db4264) update(plugins/cloudtrail): Add a region setting.

* [`b986695`](https://github.com/falcosecurity/plugins/commit/b986695) refactor(plugins/cloudtrail): isolate AWS sdk config code logic

* [`fa8e957`](https://github.com/falcosecurity/plugins/commit/fa8e957) chore(plugins/cloudtrail): use oop method declarations

* [`4df7a05`](https://github.com/falcosecurity/plugins/commit/4df7a05) update(plugins/cloudtrail): use custom sdk config files and profiles

* [`3032fd1`](https://github.com/falcosecurity/plugins/commit/3032fd1) update(plugins/cloudtrail): add aws client config overrides

* [`3a6b9ec`](https://github.com/falcosecurity/plugins/commit/3a6b9ec) update(plugins/cloudtrail): bumo plugin version to 0.6.0-rc1

* [`fe2defa`](https://github.com/falcosecurity/plugins/commit/fe2defa) update(plugins/cloudtrail): fix makefile cleanup


## v0.5.0

* [`f32982d`](https://github.com/falcosecurity/plugins/commit/f32982d) update(plugins/cloudtrail): bump version to 0.5.0


## v0.4.0

* [`a497e73`](https://github.com/falcosecurity/plugins/commit/a497e73) fix(cloudtrail): update README with uncompressed file support on S3

* [`a2023d4`](https://github.com/falcosecurity/plugins/commit/a2023d4) fix(cloudtrail): allow plain text logs in S3

* [`e05d16e`](https://github.com/falcosecurity/plugins/commit/e05d16e) update(plugins/cloudtrail): adapt plugin for plugin-sdk-go v0.4.0


## v0.3.0

* [`2e136d5`](https://github.com/falcosecurity/plugins/commit/2e136d5) refactor(plugins/cloudtrail): create package directory

* [`3446a68`](https://github.com/falcosecurity/plugins/commit/3446a68) chore(cloudtrail): move ruleset to plugin folder

* [`cc7c279`](https://github.com/falcosecurity/plugins/commit/cc7c279) update(plugins/cloudtrail): Always fill in ct.info

* [`b47bb51`](https://github.com/falcosecurity/plugins/commit/b47bb51) update(plugins/cloudtrail): Add ct.managementevent


## v0.2.5

* [`2c27a3f`](https://github.com/falcosecurity/plugins/commit/2c27a3f) update(cloudtrail): bump version to 0.2.5


## v0.2.4

* [`2e7b0f9`](https://github.com/falcosecurity/plugins/commit/2e7b0f9) update(plugins/cloudtrail): bump version

* [`2ef9014`](https://github.com/falcosecurity/plugins/commit/2ef9014) fix(plugin/cloudtrail): manage cloudtrail empty file.


## v0.2.3

* [`323f902`](https://github.com/falcosecurity/plugins/commit/323f902) update(plugins/cloudtrail): bump plugin version to 0.2.3


## v0.2.2

* [`f6b32ee`](https://github.com/falcosecurity/plugins/commit/f6b32ee) update(cloudtrail): bump verstion to 0.2.2


## v0.2.1


## v0.2.0

* [`e5e605a`](https://github.com/falcosecurity/plugins/commit/e5e605a) update(cloudtrail): bump plugin version to 0.2.0

* [`840689d`](https://github.com/falcosecurity/plugins/commit/840689d) update(cloudtrail): support init config schema in cloudtrail plugin

* [`a4b8402`](https://github.com/falcosecurity/plugins/commit/a4b8402) fix(cloudtrail): properly read init config

* [`300551c`](https://github.com/falcosecurity/plugins/commit/300551c) refactor(cloudtrail): update cloudtrail to new SDK design

* [`01e46ac`](https://github.com/falcosecurity/plugins/commit/01e46ac) refactor(cloudtrail): split files and preserve history (2)

* [`992abcc`](https://github.com/falcosecurity/plugins/commit/992abcc) refactor(cloudtrail): split files and preserve history (1)

* [`de2c4ba`](https://github.com/falcosecurity/plugins/commit/de2c4ba) WIP(cloudtrail): remove unused import

* [`37e7c9d`](https://github.com/falcosecurity/plugins/commit/37e7c9d) WIP(cloudtrail): refactor using lib


