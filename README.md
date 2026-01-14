# Plugins

[![Falco Core Repository](https://github.com/falcosecurity/evolution/blob/main/repos/badges/falco-core-blue.svg)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#core-scope) [![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/falcosecurity/evolution/blob/main/REPOSITORIES.md#stable) [![License](https://img.shields.io/github/license/falcosecurity/rules?style=for-the-badge)](./LICENSE)

This repository is the central hub for the Falco Plugin ecosystem. It serves two main purposes:

- **Be a registry:** A comprehensive catalog of plugins recognized by The Falco Project, regardless of where their source code is hosted.
- **Monorepo for Falcosecurity plugins:** Official plugins hosted and maintained by The Falco Project, with robust release and distribution processes.

For more information about the plugin system’s architecture and concepts, please see the [official documentation](https://falco.org/docs/plugins).

---

## Plugin Registry

The registry contains metadata and information about every plugin known and recognized by the Falcosecurity organization. It lists plugins hosted either in this repository or in other repositories. These plugins are developed for Falco and made available to the community. 

> Check out the [Registering a Plugin](./docs/registering-a-plugin.md) to know how to add your plugin to this registry.

### Registered Plugins

The tables below list all the plugins currently registered. The tables are automatically generated from the [registry.yaml](./registry.yaml) file.

<!-- The text inside \<!-- REGISTRY:xxx --\> comments is auto-generated.
These comments and the text between them should not be edited by hand -->
<!-- REGISTRY:TABLE -->
| Name | Capabilities | Description
| --- | --- | --- |
| plugin-id-zero-value | **Event Sourcing** <br/>ID: 0 <br/>`` | This ID is reserved for particular purposes and cannot be registered. A plugin author should not use this ID unless specified by the documentation.  <br/><br/> Authors: N/A <br/> License: N/A |
| test | **Event Sourcing** <br/>ID: 999 <br/>`test` | This ID is reserved for source plugin development. Any plugin author can use this ID, but authors can expect events from other developers with this ID. After development is complete, the author should request an actual ID  <br/><br/> Authors: N/A <br/> License: N/A |
| [k8saudit](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit) | **Event Sourcing** <br/>ID: 1 <br/>`k8s_audit` <br/>**Field Extraction** <br/> `k8s_audit` | Read Kubernetes Audit Events and monitor Kubernetes Clusters  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [cloudtrail](https://github.com/falcosecurity/plugins/tree/main/plugins/cloudtrail) | **Event Sourcing** <br/>ID: 2 <br/>`aws_cloudtrail` <br/>**Field Extraction** <br/> `aws_cloudtrail` | Reads Cloudtrail JSON logs from files/S3 and injects as events  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [json](https://github.com/falcosecurity/plugins/tree/main/plugins/json) | **Field Extraction** <br/> *All Sources* | Extract values from any JSON payload  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [dummy](https://github.com/falcosecurity/plugins/tree/main/plugins/dummy) | **Event Sourcing** <br/>ID: 3 <br/>`dummy` <br/>**Field Extraction** <br/> `dummy` | Reference plugin used to document interface  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [dummy_c](https://github.com/falcosecurity/plugins/tree/main/plugins/dummy_c) | **Event Sourcing** <br/>ID: 4 <br/>`dummy_c` <br/>**Field Extraction** <br/> `dummy_c` | Like dummy, but written in C++  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [docker](https://github.com/Issif/docker-plugin) | **Event Sourcing** <br/>ID: 5 <br/>`docker` <br/>**Field Extraction** <br/> `docker` | Docker Events  <br/><br/> Authors: [Thomas Labarussias](https://github.com/Issif) <br/> License: Apache-2.0 |
| [seccompagent](https://github.com/kinvolk/seccompagent) | **Event Sourcing** <br/>ID: 6 <br/>`seccompagent` <br/>**Field Extraction** <br/> `seccompagent` | Seccomp Agent Events  <br/><br/> Authors: [Alban Crequy](https://github.com/kinvolk/seccompagent) <br/> License: Apache-2.0 |
| [okta](https://github.com/falcosecurity/plugins/tree/main/plugins/okta) | **Event Sourcing** <br/>ID: 7 <br/>`okta` <br/>**Field Extraction** <br/> `okta` | Okta Log Events  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [github](https://github.com/falcosecurity/plugins/tree/main/plugins/github) | **Event Sourcing** <br/>ID: 8 <br/>`github` <br/>**Field Extraction** <br/> `github` | Github Webhook Events  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [k8saudit-eks](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit-eks) | **Event Sourcing** <br/>ID: 9 <br/>`k8s_audit` <br/>**Field Extraction** <br/> `k8s_audit` | Read Kubernetes Audit Events from AWS EKS Clusters  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [nomad](https://github.com/albertollamaso/nomad-plugin/tree/main) | **Event Sourcing** <br/>ID: 10 <br/>`nomad` <br/>**Field Extraction** <br/> `nomad` | Read Hashicorp Nomad Events Stream  <br/><br/> Authors: [Alberto Llamas](https://github.com/albertollamaso/nomad-plugin/issues) <br/> License: Apache-2.0 |
| [dnscollector](https://github.com/SysdigDan/dnscollector-falco-plugin) | **Event Sourcing** <br/>ID: 11 <br/>`dnscollector` <br/>**Field Extraction** <br/> `dnscollector` | DNS Collector Events  <br/><br/> Authors: [Daniel Moloney](https://github.com/SysdigDan/dnscollector-falco-plugin/issues) <br/> License: Apache-2.0 |
| [gcpaudit](https://github.com/falcosecurity/plugins/tree/main/plugins/gcpaudit) | **Event Sourcing** <br/>ID: 12 <br/>`gcp_auditlog` <br/>**Field Extraction** <br/> `gcp_auditlog` | Read GCP Audit Logs  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [syslogsrv](https://github.com/nabokihms/syslogsrv-falco-plugin/tree/main/plugins/syslogsrv) | **Event Sourcing** <br/>ID: 13 <br/>`syslogsrv` <br/>**Field Extraction** <br/> `syslogsrv` | Syslog Server Events  <br/><br/> Authors: [Maksim Nabokikh](https://github.com/nabokihms/syslogsrv-falco-plugin/issues) <br/> License: Apache-2.0 |
| [salesforce](https://github.com/an1245/falco-plugin-salesforce/) | **Event Sourcing** <br/>ID: 14 <br/>`salesforce` <br/>**Field Extraction** <br/> `salesforce` | Falco plugin providing basic runtime threat detection and auditing logging for Salesforce  <br/><br/> Authors: [Andy](https://github.com/an1245/falco-plugin-salesforce/issues) <br/> License: Apache-2.0 |
| [box](https://github.com/an1245/falco-plugin-box/) | **Event Sourcing** <br/>ID: 15 <br/>`box` <br/>**Field Extraction** <br/> `box` | Falco plugin providing basic runtime threat detection and auditing logging for Box  <br/><br/> Authors: [Andy](https://github.com/an1245/falco-plugin-box/issues) <br/> License: Apache-2.0 |
| [k8smeta](https://github.com/falcosecurity/plugins/tree/main/plugins/k8smeta) | **Field Extraction** <br/> `syscall` | Enriche Falco syscall flow with Kubernetes Metadata  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [k8saudit-gke](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit-gke) | **Event Sourcing** <br/>ID: 16 <br/>`k8s_audit` <br/>**Field Extraction** <br/> `k8s_audit` | Read Kubernetes Audit Events from GKE Clusters  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [journald](https://github.com/gnosek/falco-journald-plugin) | **Event Sourcing** <br/>ID: 17 <br/>`journal` <br/>**Field Extraction** <br/> `journal` | Read Journald events into Falco  <br/><br/> Authors: [Grzegorz Nosek](https://github.com/gnosek/falco-journald-plugin) <br/> License: Apache-2.0 |
| [kafka](https://github.com/falcosecurity/plugins/tree/main/plugins/kafka) | **Event Sourcing** <br/>ID: 18 <br/>`kafka` | Read events from Kafka topics into Falco  <br/><br/> Authors: [Hunter Madison](https://falco.org/community) <br/> License: Apache-2.0 |
| [gitlab](https://github.com/an1245/falco-plugin-gitlab) | **Event Sourcing** <br/>ID: 19 <br/>`gitlab` <br/>**Field Extraction** <br/> `gitlab` | Falco plugin providing basic runtime threat detection and auditing logging for GitLab  <br/><br/> Authors: [Andy](https://github.com/an1245/falco-plugin-gitlab/issues) <br/> License: Apache-2.0 |
| [keycloak](https://github.com/mattiaforc/falco-keycloak-plugin) | **Event Sourcing** <br/>ID: 20 <br/>`keycloak` <br/>**Field Extraction** <br/> `keycloak` | Falco plugin for sourcing and extracting Keycloak user/admin events  <br/><br/> Authors: [Mattia Forcellese](https://github.com/mattiaforc/falco-keycloak-plugin/issues) <br/> License: Apache-2.0 |
| [k8saudit-aks](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit-aks) | **Event Sourcing** <br/>ID: 21 <br/>`k8s_audit` <br/>**Field Extraction** <br/> `k8s_audit` | Read Kubernetes Audit Events from Azure AKS Clusters  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [k8saudit-ovh](https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit-ovh) | **Event Sourcing** <br/>ID: 22 <br/>`k8s_audit` <br/>**Field Extraction** <br/> `k8s_audit` | Read Kubernetes Audit Events from OVHcloud MKS Clusters  <br/><br/> Authors: [Aurélie Vache](https://falco.org/community) <br/> License: Apache-2.0 |
| [dummy_rs](https://github.com/falcosecurity/plugins/tree/main/plugins/dummy_rs) | **Event Sourcing** <br/>ID: 23 <br/>`dummy_rs` <br/>**Field Extraction** <br/> `dummy_rs` | Like dummy, but written in Rust  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [container](https://github.com/falcosecurity/plugins/tree/main/plugins/container) | **Field Extraction** <br/> `syscall` | Enriche Falco syscall flow with Container Metadata  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [krsi](https://github.com/falcosecurity/plugins/tree/main/plugins/krsi) | **Field Extraction** <br/> `syscall` | Security (KRSI) events support for Falco  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [collector](https://github.com/falcosecurity/plugins/tree/main/plugins/collector) | **Event Sourcing** <br/>ID: 24 <br/>`collector` | Generic collector to ingest raw payloads into Falco  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [awselb](https://github.com/yukinakanaka/falco-plugin-aws-elb) | **Event Sourcing** <br/>ID: 25 <br/>`awselb` <br/>**Field Extraction** <br/> `awselb` | AWS Elastic Load Balancer access logs events  <br/><br/> Authors: [Yuki Nakamura](https://github.com/yukinakanaka/falco-plugin-aws-elb/issues) <br/> License: Apache-2.0 |
| [edera](https://github.com/edera-dev/falco_plugin/) | **Event Sourcing** <br/>ID: 26 <br/>`edera_zone` <br/>**Field Extraction** <br/> `edera_zone` | A Falco plugin for forwarding libscap events out of Edera zones.  <br/><br/> Authors: [Edera](contact@edera.dev) <br/> License: Apache-2.0 |
| [nginx](https://github.com/takaosgb3/falco-plugin-nginx) | **Event Sourcing** <br/>ID: 27 <br/>`nginx` <br/>**Field Extraction** <br/> `nginx` | Real-time nginx access log monitoring for security threats.
Detects SQL injection, XSS, path traversal, command injection,
brute force attacks, and OWASP Top 10 vulnerabilities.
  <br/><br/> Authors: [takaosgb3](https://github.com/takaosgb3/falco-plugin-nginx/issues) <br/> License: Apache-2.0 |

<!-- REGISTRY:TABLE -->

## Falcosecurity Plugins

Along with the registry, this repository hosts the official plugins maintained by the Falcosecurity organization. Each plugin is an independent project with its own directory in the [plugins folder](https://github.com/falcosecurity/plugins/tree/main/plugins).

The `main` branch reflects the latest development state, and plugins are released on a regular basis. Development builds are published automatically when a Pull Request is merged into `main`, while stable builds are released only when a new tag is created. You can find all published artifacts at [download.falco.org](https://download.falco.org/?prefix=plugins). For details on the release process, please see our [Release Process](./release.md).

The instructions below explain how to install and apply only to plugins from this repository.

### Installing Plugins

Plugins hosted in this repository are built and distributed through Falco's official channels. You can easily install them using either [falcoctl](https://github.com/falcosecurity/falcoctl) or the [Falco Helm chart](https://github.com/falcosecurity/charts/tree/master/charts/falco).

#### Using falcoctl

1. **Install falcoctl:** If you haven't already, follow the [falcoctl installation guide](https://github.com/falcosecurity/falcoctl?tab=readme-ov-file#installation).
2. **Install a Plugin:** Execute the following command, replacing `<plugin-name>` with the name of the plugin you wish to install:
   ```bash
   falcoctl index update falcosecurity
   falcoctl artifact install <plugin-name>
   ```
    > Depending on your environment, you may need to run the above commands with `sudo`.
3. Configure Falco to load the plugin as described in the [plugin's documentation](https://falco.org/docs/concepts/plugins/usage/#loading-plugins-in-falco).


#### Using the Falco Helm Chart

When installing Falco using the Helm chart, you can instruct the chart to install a specific plugin by setting the `falcoctl.config.artifact.install.refs` value and then adding the relevant plugin configuration under `falco`. 

The Helm charts provides a preset [values-k8saudit.yaml](https://github.com/falcosecurity/charts/blob/master/charts/falco/values-k8saudit.yaml) file that can be used to install the `k8saudit` plugin or as example for installing other plugins.

## Contributing

If you want to help and wish to contribute, please review our [contribution guidelines](https://github.com/falcosecurity/.github/blob/main/CONTRIBUTING.md). Code contributions are always encouraged and welcome!

If you wish to contribute a plugin to The Falco Project, simply open a Pull Request to add your plugin to the `/plugins` folder and [update the registry accordingly](./docs/registering-a-plugin.md). Note that to be hosted in this repository, plugins must be licensed under the [Apache 2.0 License](./LICENSE).

### Enforcing coding style and repo policies locally

This repository supports enforcing coding style and policies locally through the `pre-commit` framework. `pre-commit`
allows to automatically install `git-hooks` that will be executed at every new commit. The following is the list of
`git-hooks` defined in `.pre-commit-config.yaml` (notice that some of them only target files written in a specific
language):
1. the `rust-fmt` hook - a `pre-commit` git hook running `rust fmt` on the staged changes
2. the `dco` hook - a `pre-commit-msg` git hook running adding the `DCO` on the commit if not present

The following steps describe how to install these hooks.

##### Step 1

Install `pre-commit` framework following the [official documentation](https://pre-commit.com/#installation).

> __Please note__: you have to follow only the "Installation" section.

#### Step 2

Install `pre-commit` git hooks:
```bash
pre-commit install --hook-type pre-commit --hook-type prepare-commit-msg  --overwrite
```

## License

This project is licensed to you under the [Apache 2.0 Open Source License](./LICENSE).


