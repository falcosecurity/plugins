# Changelog

## v0.13.0

* [`ecff28f`](https://github.com/falcosecurity/plugins/commit/ecff28f8) update(cloudtrail): bump to v0.13.0

* [`ce4e3fc`](https://github.com/falcosecurity/plugins/commit/ce4e3fcf) build(deps): bump github.com/aws/aws-lambda-go in /plugins/cloudtrail

* [`65c9973`](https://github.com/falcosecurity/plugins/commit/65c9973a) chore(cloudtrail): allow SQSOwnerAccount parameter

* [`ba252e3`](https://github.com/falcosecurity/plugins/commit/ba252e31) update(plugins/cloudtrail): upgrade deps


## v0.12.5

* [`f2fe57d`](https://github.com/falcosecurity/plugins/commit/f2fe57d1) update(plugins/cloudtrail): support pre-ControlTower organization trails

* [`2ea1083`](https://github.com/falcosecurity/plugins/commit/2ea10833) update(plugins/cloudtrail): upgrade direct deps


## v0.12.4

* [`9663407`](https://github.com/falcosecurity/plugins/commit/96634075) build(deps): bump github.com/aws/aws-sdk-go-v2 in /plugins/cloudtrail

* [`f6e5098`](https://github.com/falcosecurity/plugins/commit/f6e5098d) update(plugins/cloudtrail): bump to v0.12.3

* [`56c0599`](https://github.com/falcosecurity/plugins/commit/56c0599e) build(deps): bump github.com/invopop/jsonschema in /plugins/cloudtrail


## v0.12.3

* [`fbd9f48`](https://github.com/falcosecurity/plugins/commit/fbd9f483) update(cloudtrail): Update ct.resources handling


## v0.12.2

* [`63b7093`](https://github.com/falcosecurity/plugins/commit/63b70933) chore(plugin/cloudtrail): bump cloudtrail version to 0.10.0


## v0.12.1

* [`c4ed2ca`](https://github.com/falcosecurity/plugins/commit/c4ed2ca4) chore(plugins/cloudtrail): update changelog

* [`d775f53`](https://github.com/falcosecurity/plugins/commit/d775f538) chore(cloudtrail): replace moved package

* [`f43ca43`](https://github.com/falcosecurity/plugins/commit/f43ca433) chore(cloudtrail): update Go and dependencies


## v0.12.0

* [`b31948c`](https://github.com/falcosecurity/plugins/commit/b31948c1) refactor(cloudtrail): Get S3 keys concurrently

* [`9920d35`](https://github.com/falcosecurity/plugins/commit/9920d355) feat(cloudtrail): support accounts for org trails

* [`746ea98`](https://github.com/falcosecurity/plugins/commit/746ea983) feat(cloudtrail): Support for organization trails

* [`9a1f86a`](https://github.com/falcosecurity/plugins/commit/9a1f86a1) feat(cloudtrail): Add generic additionalEventData field

* [`0e4a687`](https://github.com/falcosecurity/plugins/commit/0e4a6873) feat(cloudtrail): Add ct.response and ct.request field


## v0.11.0


## v0.10.0


## v0.9.1

* [`16306f2`](https://github.com/falcosecurity/plugins/commit/16306f2f) update(cloudtrail): bump version to 0.9.1

* [`66c77be`](https://github.com/falcosecurity/plugins/commit/66c77beb) fix(plugins/cloudtrail): remove wrong return statement when extracting recipi...


## v0.9.0

* [`3156ed5`](https://github.com/falcosecurity/plugins/commit/3156ed57) fix(plugins/cloudtrail): Generate the correct interval values

* [`5bbc310`](https://github.com/falcosecurity/plugins/commit/5bbc3102) update(plugins/cloudtrail): Make our default interval ""

* [`431bcf8`](https://github.com/falcosecurity/plugins/commit/431bcf8f) update(plugins/cloudtrail): Remove a dependency

* [`ef52d3c`](https://github.com/falcosecurity/plugins/commit/ef52d3cd) update(plugins/cloudtrail): Fix a time comparison

* [`c02b076`](https://github.com/falcosecurity/plugins/commit/c02b076d) update(plugins/cloudtrail): Add an S3Interval option

* [`4b1156b`](https://github.com/falcosecurity/plugins/commit/4b1156b6) update(plugins/cloudtrail): Add dependencies to our Makefile

* [`9a0ec0d`](https://github.com/falcosecurity/plugins/commit/9a0ec0d3) update(plugins/cloudtrail): Increase our default S3 concurrency


## v0.8.0

* [`9f36290`](https://github.com/falcosecurity/plugins/commit/9f362901) update(plugins/cloudtrail): Avoid duplicate event info


## v0.7.3

* [`3bac296`](https://github.com/falcosecurity/plugins/commit/3bac2962) fix(plugins/cloudtrail): fix ruleset dependencies


## v0.7.2

* [`0c07efc`](https://github.com/falcosecurity/plugins/commit/0c07efc2) feature(plugins/cloudtrail): add fields to plugin

* [`501f351`](https://github.com/falcosecurity/plugins/commit/501f3511) fix(plugins/cloudtrail): if accountId not present in userIdentity, set it to ...


## v0.7.1


## v0.7.0

* [`3c6009b`](https://github.com/falcosecurity/plugins/commit/3c6009b8) update(plugins/cloudtrail): bump plugin version to v0.7.0

* [`8984655`](https://github.com/falcosecurity/plugins/commit/8984655e) update(rules/cloudtrail): bump required_plugins_versions for cloudtrail rules

* [`505a308`](https://github.com/falcosecurity/plugins/commit/505a3088) update(plugins/cloudtrail): More friendly error messages


## v0.6.0

* [`0571948`](https://github.com/falcosecurity/plugins/commit/0571948f) update(plugins/cloudtrail): bump plugin version to v0.6.0

* [`1db4264`](https://github.com/falcosecurity/plugins/commit/1db42649) update(plugins/cloudtrail): Add a region setting.

* [`b986695`](https://github.com/falcosecurity/plugins/commit/b9866951) refactor(plugins/cloudtrail): isolate AWS sdk config code logic

* [`fa8e957`](https://github.com/falcosecurity/plugins/commit/fa8e9571) chore(plugins/cloudtrail): use oop method declarations

* [`4df7a05`](https://github.com/falcosecurity/plugins/commit/4df7a058) update(plugins/cloudtrail): use custom sdk config files and profiles

* [`3032fd1`](https://github.com/falcosecurity/plugins/commit/3032fd1f) update(plugins/cloudtrail): add aws client config overrides

* [`3a6b9ec`](https://github.com/falcosecurity/plugins/commit/3a6b9ec4) update(plugins/cloudtrail): bumo plugin version to 0.6.0-rc1

* [`fe2defa`](https://github.com/falcosecurity/plugins/commit/fe2defae) update(plugins/cloudtrail): fix makefile cleanup


## v0.5.0

* [`f32982d`](https://github.com/falcosecurity/plugins/commit/f32982d6) update(plugins/cloudtrail): bump version to 0.5.0


## v0.4.0

* [`a497e73`](https://github.com/falcosecurity/plugins/commit/a497e730) fix(cloudtrail): update README with uncompressed file support on S3

* [`a2023d4`](https://github.com/falcosecurity/plugins/commit/a2023d4f) fix(cloudtrail): allow plain text logs in S3

* [`e05d16e`](https://github.com/falcosecurity/plugins/commit/e05d16ea) update(plugins/cloudtrail): adapt plugin for plugin-sdk-go v0.4.0


## v0.3.0

* [`2e136d5`](https://github.com/falcosecurity/plugins/commit/2e136d54) refactor(plugins/cloudtrail): create package directory

* [`3446a68`](https://github.com/falcosecurity/plugins/commit/3446a683) chore(cloudtrail): move ruleset to plugin folder

* [`cc7c279`](https://github.com/falcosecurity/plugins/commit/cc7c279c) update(plugins/cloudtrail): Always fill in ct.info

* [`b47bb51`](https://github.com/falcosecurity/plugins/commit/b47bb515) update(plugins/cloudtrail): Add ct.managementevent


## v0.2.5

* [`2c27a3f`](https://github.com/falcosecurity/plugins/commit/2c27a3f9) update(cloudtrail): bump version to 0.2.5


## v0.2.4

* [`2e7b0f9`](https://github.com/falcosecurity/plugins/commit/2e7b0f9c) update(plugins/cloudtrail): bump version

* [`2ef9014`](https://github.com/falcosecurity/plugins/commit/2ef9014d) fix(plugin/cloudtrail): manage cloudtrail empty file.


## v0.2.3

* [`323f902`](https://github.com/falcosecurity/plugins/commit/323f9022) update(plugins/cloudtrail): bump plugin version to 0.2.3


## v0.2.2

* [`f6b32ee`](https://github.com/falcosecurity/plugins/commit/f6b32ee7) update(cloudtrail): bump verstion to 0.2.2


## v0.2.1


## v0.2.0

* [`e5e605a`](https://github.com/falcosecurity/plugins/commit/e5e605a6) update(cloudtrail): bump plugin version to 0.2.0

* [`840689d`](https://github.com/falcosecurity/plugins/commit/840689d9) update(cloudtrail): support init config schema in cloudtrail plugin

* [`a4b8402`](https://github.com/falcosecurity/plugins/commit/a4b8402e) fix(cloudtrail): properly read init config

* [`300551c`](https://github.com/falcosecurity/plugins/commit/300551ce) refactor(cloudtrail): update cloudtrail to new SDK design

* [`01e46ac`](https://github.com/falcosecurity/plugins/commit/01e46ac9) refactor(cloudtrail): split files and preserve history (2)

* [`992abcc`](https://github.com/falcosecurity/plugins/commit/992abcc3) refactor(cloudtrail): split files and preserve history (1)

* [`de2c4ba`](https://github.com/falcosecurity/plugins/commit/de2c4bac) WIP(cloudtrail): remove unused import

* [`37e7c9d`](https://github.com/falcosecurity/plugins/commit/37e7c9dd) WIP(cloudtrail): refactor using lib


