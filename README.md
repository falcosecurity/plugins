# falcosecurity/plugins

Status: **Under development**

Note: The plugin system is a new feature and is still under active development. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md). Since this feature has not yet been released in Falco, consider it as experimental at the moment. 

This repository contains several reference [plugins](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/) that extend the functionality of Falco: The `dummy` and `dummy_c` plugins are used in the [developer's guide](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/developers_guide/) to walk through how to write a plugin.

You can find pre-built versions of the [cloudtrail](./plugins/cloudtrail/) and [json](./plugins/json/) plugins in falco packages. They are not enabled by default--read the [documentation](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins) for how to modify `falco.yaml` to enable them and configure them with inputs.

When ready to release your plugin, make sure to register the plugin with the Falcosecurity organization by creating a PR to modify the [registry.yaml](https://github.com/andreabonanno/plugins/blob/refactor/new-registry-format/registry/registry.yaml) file with details on the new plugin. This ensures that a given ID is used by exactly one source plugin, and allows source plugin authors and extractor plugin authors to coordinate about event source formats.

# Plugin Registry

<!-- The text inside \<!-- REGISTRY --\> comments is auto-generated. These comments and the text between them should not be edited by hand -->
<!-- REGISTRY -->
## Source Plugins
| ID | Name | Event Source | Description | Info |
| --- | --- | --- | --- | --- |
| 1 | k8s_audit | `k8s_audit` | Reserved for a future back-port of Falco's k8s_audit event source as a plugin | Authors: N/A <br/> License: N/A |
| 2 | [cloudtrail](https://github.com/falcosecurity/plugins/tree/master/plugins/cloudtrail) | `aws_cloudtrail` | Reads Cloudtrail JSON logs from files/S3 and injects as events | Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| 3 | [dummy](https://github.com/falcosecurity/plugins/tree/master/plugins/dummy) | `dummy` | Reference plugin used to document interface | Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| 4 | [dummy_c](https://github.com/falcosecurity/plugins/tree/master/plugins/dummy_c) | `dummy_c` | Like Dummy, but written in C++ | Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |
| 999 | test | `test` | This ID is reserved for source plugin development. Any plugin author can use this ID, but authors can expect events from other developers with this ID. After development is complete, the author should request an actual ID | Authors: N/A <br/> License: N/A |

## Extractor Plugins
| Name | Extract Event Sources | Description | Info |
| --- | --- | --- | --- |
| [json](https://github.com/falcosecurity/plugins/tree/master/plugins/json) | N/A | Extract values from any JSON payload | Authors: [The Falco Authors](https://falco.org/community) <br/> License: Apache-2.0 |

<!-- REGISTRY -->

