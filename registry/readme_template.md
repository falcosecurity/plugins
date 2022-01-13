# falcosecurity/plugins

Status: **Under development**

Note: The plugin system is a new feature and is still under active development. You can find more detail in the original [proposal document](https://github.com/falcosecurity/falco/blob/master/proposals/20210501-plugin-system.md). Since this feature has not yet been released in Falco, consider it as experimental at the moment. 

This repository contains several reference [plugins](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/) that extend the functionality of Falco: The `dummy` and `dummy_c` plugins are used in the [developer's guide](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/developers_guide/) to walk through how to write a plugin.

You can find pre-built versions of the [cloudtrail](./plugins/cloudtrail/) and [json](./plugins/json/) plugins in falco packages. They are not enabled by default--read the [documentation](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins) for how to modify `falco.yaml` to enable them and configure them with inputs.

When ready to release your plugin, make sure to register the plugin with the Falcosecurity organization by creating a PR to modify the [PLUGINS-REGISTRY.md](https://github.com/falcosecurity/plugins/blob/master/plugins/PLUGINS-REGISTRY.md) file with details on the new plugin. This ensures that a given ID is used by exactly one source plugin, and allows source plugin authors and extractor plugin authors to coordinate about event source formats.
