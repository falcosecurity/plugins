# Plugins

![GitHub branch checks state](https://img.shields.io/github/checks-status/falcosecurity/plugins/master?style=for-the-badge)
[![License](https://img.shields.io/github/license/falcosecurity/plugins?style=for-the-badge)](./LICENSE)

Note: *The plugin system is a new feature introduced since Falco 0.31.0. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md).*

This repository contains the [Plugin Registry](#plugin-registry) and the [plugins officially maintained](#falcusecurity-plugins) by the Falcosecurity organization. [Plugins](https://falco.org/docs/plugins) can be used to extend [Falco](https://github.com/falcosecurity/falco) and of applications using [Falcosecurity libs](https://github.com/falcosecurity/libs). Please refer to the [official documentation](https://falco.org/docs/plugins) to better understand the plugin system's concepts and architecture. 

## Plugin Registry

The Registry contains metadata and information about every plugin known and recognized by the Falcosecurity organization. It lists plugins hosted either in this repository or in other repositories. These plugins are developed for Falco and made available to the community. Check out the sections below to know how to [register your plugins](#registering-a-new-plugin) and see plugins currently contained in the registry.

### Registering a new Plugin

Registering your plugin inside the registry helps ensure that some technical constraints are respected, such as that a [given ID is used by exactly one plugin with event source capability](https://falco.org/docs/plugins/#plugin-event-ids) and allows plugin authors to [coordinate about event source formats](https://falco.org/docs/plugins/#plugin-event-sources-and-interoperability). Moreover, this is a great way to share your plugin project with the community and engage with it, thus gaining new users and **increasing its visibility**. We encourage you to register your plugin in this registry before publishing it. You can add your plugins in this registry regardless of where its source code is hosted (there's a `url` field for this specifically).

The registration process involves adding an entry about your plugin inside the [registry.yaml](./registry.yaml) file by creating a Pull Request in this repository. Please be mindful of a few constraints that are automatically checked and required for your plugin to be accepted:

- The `name` field is mandatory and must be **unique** across all the plugins in the registry
- *(Sourcing Capability Only)* The `id` field is mandatory and must be **unique** in the registry across all the plugins with event source capability
- The plugin `name` must match this [regular expression](https://en.wikipedia.org/wiki/Regular_expression): `^[a-z]+[a-z0-9-_]*$` (however, its not reccomended to use `_` in the name, unless you are trying to match the name of a source or for particular reasons)
- The `source` *(Sourcing Capability Only)* and `sources` *(Extraction Capability Only)* must match this [regular expression](https://en.wikipedia.org/wiki/Regular_expression): `^[a-z]+[a-z0-9_]*$`
- The `url` field should point to the plugin source code
- The `rules_url` field should point to the default ruleset, if any

For reference, here's an example of an entry for a plugin with both event sourcing and field extraction capabilities:
```yaml
- name: k8saudit
  description: ...
  authors: ...
  contact: ...
  maintainers:
    - name: The Falco Authors
      email: cncf-falco-dev@lists.cncf.io
  keywords:
    - audit
    - audit-log
    - audit-events
    - kubernetes
    url: https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit
    rules_url: https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit/rules
  url: ...
  license: ...
  capabilities:
    sourcing:
      supported: true
      id: 2
      source: k8s_audit
    extraction:
      supported: true
```

You can find the full registry specification here: *(coming soon...)*

### Registered Plugins

The tables below list all the plugins currently registered. The tables are automatically generated from the [registry.yaml](./registry.yaml) file.

<!-- The text inside \<!-- REGISTRY:xxx --\> comments is auto-generated.
These comments and the text between them should not be edited by hand -->
<!-- REGISTRY:TABLE -->
| Name | Capabilities | Description
| --- | --- | --- |
| [k8saudit](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit) | **Event Sourcing** <br/>ID: 1 <br/>`k8s_audit` <br/>**Field Extraction** <br/> `k8s_audit` | Read Kubernetes Audit Events and monitor Kubernetes Clusters  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [cloudtrail](https://github.com/falcosecurity/plugins/tree/master/plugins/cloudtrail) | **Event Sourcing** <br/>ID: 2 <br/>`aws_cloudtrail` <br/>**Field Extraction** <br/> `aws_cloudtrail` | Reads Cloudtrail JSON logs from files/S3 and injects as events  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [json](https://github.com/falcosecurity/plugins/tree/master/plugins/json) | **Field Extraction** <br/> *All Sources* | Extract values from any JSON payload  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [dummy](https://github.com/falcosecurity/plugins/tree/master/plugins/dummy) | **Event Sourcing** <br/>ID: 3 <br/>`dummy` <br/>**Field Extraction** <br/> `dummy` | Reference plugin used to document interface  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [dummy_c](https://github.com/falcosecurity/plugins/tree/master/plugins/dummy_c) | **Event Sourcing** <br/>ID: 4 <br/>`dummy_c` <br/>**Field Extraction** <br/> `dummy_c` | Like dummy, but written in C++  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [docker](https://github.com/Issif/docker-plugin) | **Event Sourcing** <br/>ID: 5 <br/>`docker` <br/>**Field Extraction** <br/> `docker` | Docker Events  <br/><br/> Authors: [Thomas Labarussias](https://github.com/Issif) <br/> License: Apache-2.0 |
| [seccompagent](https://github.com/kinvolk/seccompagent) | **Event Sourcing** <br/>ID: 6 <br/>`seccompagent` <br/>**Field Extraction** <br/> `seccompagent` | Seccomp Agent Events  <br/><br/> Authors: [Alban Crequy](https://github.com/kinvolk/seccompagent) <br/> License: Apache-2.0 |
| [okta](https://github.com/falcosecurity/plugins/tree/master/plugins/okta) | **Event Sourcing** <br/>ID: 7 <br/>`okta` <br/>**Field Extraction** <br/> `okta` | Okta Log Events  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [github](https://github.com/falcosecurity/plugins/tree/master/plugins/github) | **Event Sourcing** <br/>ID: 8 <br/>`github` <br/>**Field Extraction** <br/> `github` | Github Webhook Events  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| [k8saudit-eks](https://github.com/falcosecurity/plugins/tree/master/plugins/k8saudit-eks) | **Event Sourcing** <br/>ID: 9 <br/>`k8s_audit` <br/>**Field Extraction** <br/> `k8s_audit` | Read Kubernetes Audit Events from AWS EKS Clusters  <br/><br/> Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| test | **Event Sourcing** <br/>ID: 999 <br/>`test` | This ID is reserved for source plugin development. Any plugin author can use this ID, but authors can expect events from other developers with this ID. After development is complete, the author should request an actual ID  <br/><br/> Authors: N/A <br/> License: N/A |

<!-- REGISTRY:TABLE -->

## Hosted Plugins 

Another purpose of this repository is to host and maintain the plugins owned by the Falcosecurity organization. Each plugin is a standalone project and has its own directory, and they are all inside the [plugins](https://github.com/falcosecurity/plugins/tree/master/plugins) folder.

The `master` branch contains the most up-to-date state of development, and each plugin is regularly released. Please check our [Release Process](./release.md) to know how plugins are released and how artifacts are distributed. Dev builds are published each time a Pull Request gets merged into `master`, whereas stable builds are released and published only when a new release gets tagged. You can find the published artifacts at https://download.falco.org/?prefix=plugins.

If you wish to contribute your plugin to the Falcosecurity organization, you just need to open a Pull Request to add it inside the `plugins` folder and to add it inside the registry. In order to be hosted in this repository, plugins must be licensed under the [Apache 2.0 License](./LICENSE). 

## Contributing

If you want to help and wish to contribute, please review our [contribution guidelines](https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md). Code contributions are always encouraged and welcome!

## License

This project is licensed to you under the [Apache 2.0 Open Source License](./LICENSE).


