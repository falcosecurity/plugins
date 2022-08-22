# Falcosecurity Dummy Plugin

This directory contains the dummy plugin, which is an example plugin written in Go. It's referenced in the [Plugins Go SDK Walkthrough](https://falco.org/docs/plugins/go-sdk-walkthrough/#example-go-plugin-dummy) as an implementation example of a plugin with both event sourcing and field extraction capabilities.

It generates synthetic events and doesn't serve any purpose other than for documentation.

## Event Source

The event source for dummy events is `dummy`.

## Supported Fields

Here is the current set of supported fields:

<!-- README-PLUGIN-FIELDS -->
|       NAME        |   TYPE   |      ARG      |                               DESCRIPTION                               |
|-------------------|----------|---------------|-------------------------------------------------------------------------|
| `dummy.divisible` | `uint64` | Key, Required | Return 1 if the value is divisible by the provided divisor, 0 otherwise |
| `dummy.value`     | `uint64` | None          | The sample value in the event                                           |
| `dummy.strvalue`  | `string` | None          | The sample value in the event, as a string                              |
<!-- /README-PLUGIN-FIELDS -->

## Configuration

### Plugin Initialization

The format of the initialization string is a json object. Here's an example:

```json
{"jitter": 10}
```

The json object has the following properties:

* `jitter`: Controls the random value that is added to each event returned in next().

The init string can be the empty string, which is treated identically to `{}`.

### Plugin Open Params

The open parameters is a positive integer which denotes the number of samples to generate before returning EOF.

The plugin is capable of suggesting a list of simple valid open parameters.

### `falco.yaml` Example

Here is a complete `falco.yaml` snippet showing valid configurations for the dummy plugin:

```yaml
plugins:
  - name: dummy
    library_path: libdummy.so
    init_config:
      jitter: 10
    open_params: 100  # generate 100 events

load_plugins: [dummy]
```
