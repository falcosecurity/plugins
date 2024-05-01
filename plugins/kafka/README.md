# Kafka Events Plugin

This repository contains the `kafka` plugin for `Falco`.

# Event Source

The event source for `kafka` events is `kafka`.

# Supported Fields

This plugin does not provide field extraction.

# Development
## Requirements

You need:
* `Go` >= 1.22.2

## Build

```shell
make
```

# Settings

Only `init` accepts settings:

* `brokers`: The list of Kafka brokers to consume messages from.
* `groupId`: The consumer group identifier.
* `topics`: The topics to consume from.
* `tlsConfig`: Configuration for TLS encryption.

# Configurations

* `falco.yaml`

  ```yaml
  plugins:
    - name: kafka
      library_path: /usr/share/falco/plugins/libkafka.so
      init_config:
        init_config: |
          {
            "brokers": ["host.docker.internal:9094"],
            "topics": ["example2"],
            "groupId": "example1",
            "tlsConfig": {
              "caCertPath": "/mnt/certs/ca.pem",
              "userCertPath": "/mnt/certs/user.pem",
              "userKeyPath": "/mnt/certs/key.pem"
            }
          }
      open_params: ''

  load_plugins: [kafka]
  ```