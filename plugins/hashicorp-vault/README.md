# Hashicorp Vault Events Plugin

This repository contains the `hashicorp-vault` plugin for `Falco`, which fetch log [events](https://developer.hashicorp.com/vault/docs/concepts/events) from an [Hashicorp Vault](https://www.vaultproject.io/) instance and emit sinsp/scap events (e.g. the events used by `Falco`) for each entry.

The plugin also exports fields that extract information from a `hashicorp-vault` log event, such as the event time, the event type, the mount class, the mount path, ...

- [Hashicorp Vault Events Plugin](#hashicorp-vault-events-plugin)
- [Event Source](#event-source)
- [Supported Fields](#supported-fields)
- [Development](#development)
  - [Requirements](#requirements)
  - [Build](#build)
- [Settings](#settings)
- [Configurations](#configurations)
- [Usage](#usage)
  - [Requirements](#requirements-1)
  - [Results](#results)

# Event Source

The event source for `hashicorp-vault` events is `hashicorpvault`.

# Supported Fields

<!-- README-PLUGIN-FIELDS -->
|                   NAME                   |   TYPE   | ARG  |                 DESCRIPTION                 |
|------------------------------------------|----------|------|---------------------------------------------|
| `hashicorpvault.event.id`                | `string` | None | CloudEvents unique identifier for the event |
| `hashicorpvault.event.type`              | `string` | None | The event type that was published           |
| `hashicorpvault.metadata.currentversion` | `string` | None | Current version of the object               |
| `hashicorpvault.metadata.oldestversion`  | `string` | None | Oldest version of the object                |
| `hashicorpvault.metadata.path`           | `string` | None | Path of the object                          |
| `hashicorpvault.plugin.mountclass`       | `string` | None | The class of the plugin                     |
| `hashicorpvault.plugin.mountaccessor`    | `string` | None | The unique ID of the mounted plugin         |
| `hashicorpvault.plugin.mountpath`        | `string` | None | The path that the plugin is mounted at      |
| `hashicorpvault.plugin.name`             | `string` | None | The name of the plugin                      |
<!-- /README-PLUGIN-FIELDS -->

# Development
## Requirements

You need:
* `Go` >= 1.17

## Build

```shell
make
```

# Settings

Only `init` accepts settings:
* `token`: your Token to access Hashicorp Vault API
* `host_port`: Host:Port of your Hashicrop Vault instance (ex: *localhost:8200*)

# Configurations

* `falco.yaml`

  ```yaml
  plugins:
    - name: hashicorp-vault
      library_path: /usr/share/falco/plugins/libhashicorp-vault.so
      init_config:
        token: xxxxxxxxxxx
        host_port: localhost:8200
      open_params: ''

  load_plugins: [hashicorp-vault]
  ```

* `rules.yaml`

The `source` for rules must be `hashicorp-vault`.

See example:
```yaml
- rule: Secret update
  desc: Secret update
  condition: hashicorpvault.event.type="kv-v2/data-write"
  output: The secret %hashicorpvault.metadata.path in the engine %hashicorpvault.plugin.mountpath has been updated to version %hashicorpvault.metadata.currentversion
  priority: NOTICE
  source: hashicorpvault
  tags: [hashicorp-vault]
- rule: Secret delete
  desc: Secret delete
  condition: hashicorpvault.event.type="kv-v2/metadata-delete"
  output: The secret %hashicorpvault.metadata.path in the engine %hashicorpvault.plugin.mountpath has been deleted
  priority: WARNING
  source: hashicorpvault
  tags: [hashicorp-vault]
```

# Usage

```shell
falco -c falco.yaml -r hashicorp-vault_rules.yaml
```

## Requirements

* `Falco` >= 0.31

## Results

```shell
2023-05-16T16:26:27.687301000+0000: Notice The secret data/secret00 in the engine mysecrets/ has been updated to version 4
2023-05-16T16:26:34.384587000+0000: Notice The secret data/secret00 in the engine mysecrets/ has been updated to version 5
2023-05-16T16:26:39.393935000+0000: Warning The secret metadata/secret00 in the engine mysecrets/ has been deleted
```
