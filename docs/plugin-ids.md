# Plugin IDs (Sourcing Capability Only)

Using a unique `id` is mandatory to maintain interoperability across all plugins with _event sourcing_ capability. When a plugin is loaded by a compatible application (e.g., Falco), the `id` is used to route events to the correct plugin. Indeed, attempting to load two or more plugins using the same `id` will result in an error.

For this reason, The Falco Project maintains a [public registry of plugins](https://github.com/falcosecurity/plugins/blob/main/README.md#registering-a-new-plugin), which allows the assignment of a unique `id` for your plugin. However, some plugins may not be registered in the public registry. For example, if you are privately developing a plugin for your own use, you might use any `id` you want. To avoid conflicts in these situations, this document mandates general rules regarding `id` assignment and reservation.

## ID Blocks

The following ID ranges are designated for specific purposes:

| Block name | ID range | # of IDs | Description |
|---|---|---|---|
| Public | 0–1073741823 (30-bit) | 1073741824 | Used in the public registry. Single IDs in this range can be [assigned](#assigning-an-id) or [reserved](#reserving-an-id). |
| Private | 1073741824–2147483647 (30-bit) | 1073741824 | Used for private plugins (think of this range as the equivalent of 192.168.0.0/16 in networks). Organizations may use this range for plugins intended for their private domain. Interoperability is not guaranteed. |
| Reserved | 2147483648-3221225471 (30-bit) | 1073741824 | This range is reserved for future use and must not be used under any circumstances. |
| Internal | 3221225472-4294967295 (30-bit) | 1073741824 | This range is reserved for internal use and must not be used by plugins. It might be used by the plugin framework implementation for technical purposes. |

Notes:
- An `id` is a 32-bit unsigned integer. The MSBs are used to identify the block of IDs.
- Only IDs up to 1073741823 can be requested for use in the public registry.
- Only IDs up to 2147483647 can be used by plugins.

## Assigning an ID

The public registry is intended for assigning IDs to plugins that are publicly available. If you want to share your plugin with the community, you should follow the instructions reported in the [Registering a new plugin](../README.md#registering-a-new-plugin) section of this repository's documentation.

When making your request, please choose the next available ID in the [registry.yaml](../registry.yaml) file. The `id` will be definitively assigned to your plugin once the corresponding PR is merged, and the [registry.yaml](../registry.yaml) file is updated.

## Reserving an ID

For particular technical purposes or special cases, an `id` can be reserved so that it will not be assigned to any specific plugin. Notably, id 999 has been reserved for source plugin development. Any plugin author can temporarily use this `id`; however, it can't be assigned to any specific plugin and must not be used for purposes other than local development.

To reserve an `id`, you can use the same procedure for [registering a new plugin](../README.md#registering-a-new-plugin) and specify the `reserved: true` option.

Requests for `id` reservation will be evaluated on a case-by-case basis. The Falco Project reserves the right to reject any request for any reason.