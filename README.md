# falcosecurity/plugins

This repository contains several reference [plugins](https://falco.org/docs/plugins) that extend the functionality of Falco: The `dummy` and `dummy_c` plugins are used in the [developer's guide](https://falco.org/docs/plugins/developers_guide/) to walk through how to write a plugin.

When ready to release your plugin, make sure to register the plugin with the Falcosecurity organization by creating a PR to modify the [PLUGINS-REGISTRY.md](https://github.com/falcosecurity/plugins/blob/master/plugins/PLUGINS-REGISTRY.md) file with details on the new plugin. This ensures that a given ID is used by exactly one source plugin, and allows source plugin authors and extractor plugin authors to coordinate about event source formats.

