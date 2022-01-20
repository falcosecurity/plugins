# Plugins

Note: *The plugin system is a new feature introduced since Falco 0.31.0. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md).*

This repository contains the [Plugin Registry](#plugin-registry) and the [plugins officially maintained](#falcusecurity-plugins) by the Falcosecurity organization. [Plugins](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins) can be used to extend the functionality of [Falco](https://github.com/falcosecurity/falco) and of applications using [Falcosecurity libs](https://github.com/falcosecurity/libs). Please refer to the [official documentation](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/) to better understand the concepts and the architecture behind the plugin system. 

## Plugin Registry

The Registry contains metadata and information about every plugin known and recognized by the Falcosecurity organization. These every plugin developed for Falco and made available to the community, including the ones contained in this repository. Check out the sections below to know how to [register your plugins]([registering](#registering-a-new-plugin)), and to see plugins currently contained in the registry.

### Registering a new Plugin

Registering your plugin inside the registry helps ensuring that some technical constraints are respected, such as that a [given ID is used by exactly one source plugin](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/#plugin-event-ids), and allows source plugin authors and extractor plugin authors to [coordinate about event source formats](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/#plugin-event-sources-and-interoperability). Moreover, this is a great way to share your plugin project with the community and engage with it, thus gaining new users and **increase its visibility**. We encourage you to register your plugin in this registry before publishing it. You can add your plugins in this registry regardless of where its source code is hosted (there's a `url` field for this specifically).

The registration process consists in adding an entry about your plugin inside the [registry.yaml](./registry.yaml) file by creating a Pull Request in this repository. Please be mindful of few constraints that are automatically checked and required for your plugin to be accepted:

- The `name` field is mandatory and must be **unique** across all the plugins in the registry
- *(Source plugins only)* The `id` and `source` fields are mandatory and must be **unique** across all the source plugins in the registry
- The plugin `name` and `source` fields should match this [regular expression](https://en.wikipedia.org/wiki/Regular_expression): `^[a-z]+[a-z0-9_]*$`

For reference, here's an example of a source plugin entry:
```yaml
- id: 2
  source: aws_cloudtrail
  name: cloudtrail
  description: ...
  authors: The Falco Authors
  contact: https://falco.org/community
  url: ...
  license: Apache-2.0
```

You can find the full registry specification here: *(coming soon...)*

### Registered Plugins

The tables below list the all plugins currently registered. The tables are are automatically generated from [registry.yaml](./registry.yaml).

<!-- The text inside \<!-- REGISTRY --\> comments is auto-generated. These comments and the text between them should not be edited by hand -->
<!-- REGISTRY -->
#### Source Plugins
| ID | Name | Event Source | Description | Info |
| --- | --- | --- | --- | --- |
| 1 | k8s_audit | `k8s_audit` | Reserved for a future back-port of Falco's k8s_audit event source as a plugin | Authors: N/A <br/> License: N/A |
| 2 | [cloudtrail](https://github.com/falcosecurity/plugins/tree/master/plugins/cloudtrail) | `aws_cloudtrail` | Reads Cloudtrail JSON logs from files/S3 and injects as events | Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| 3 | [dummy](https://github.com/falcosecurity/plugins/tree/master/plugins/dummy) | `dummy` | Reference plugin used to document interface | Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| 4 | [dummy_c](https://github.com/falcosecurity/plugins/tree/master/plugins/dummy_c) | `dummy_c` | Like Dummy, but written in C++ | Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| 999 | test | `test` | This ID is reserved for source plugin development. Any plugin author can use this ID, but authors can expect events from other developers with this ID. After development is complete, the author should request an actual ID | Authors: N/A <br/> License: N/A |

#### Extractor Plugins
| Name | Extract Event Sources | Description | Info |
| --- | --- | --- | --- |
| [json](https://github.com/falcosecurity/plugins/tree/master/plugins/json) | N/A | Extract values from any JSON payload | Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |

<!-- REGISTRY -->



## Hosted Plugins 

Another purpose of this repository is to host and maintain the plugins owned by the Falcosecurity organization. Each plugin is a standalone project and has its own directory, and they are all inside `plugins` folder.

The `master` branch contains the most up-to-date state of development, and each plugin is regularly released. Please check our [Release Process](./release.md) to know about how plugins are released and how artifacts are distributed. Dev builds are published each time a Pull Request gets merged into `master`, whereas stable builds are released and published only when a new releases gets tagged. You can find the published artifacts at https://download.falco.org/?prefix=plugins.

If you wish to contribute your plugin to the Falcosecurity organization, you just need to open a Pull Request to add it inside the `plugins` folder and to add it inside the registry. In order to be hosted in this repository, plugins must be licensed under the [Apache 2.0 License](./LICENSE). 

## Contributing

If you want to help and wish to contribute, please review our [contribution guidelines](https://github.com/falcosecurity/.github/blob/master/CONTRIBUTING.md). Code contributions are always encouraged and welcome!

## License

This project is licensed to you under the [Apache 2.0 Open Source License](./LICENSE).


