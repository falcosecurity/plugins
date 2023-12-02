# Falcosecurity Dummy Plugin

This directory contains the dummy plugin, which is an example plugin written in Go. It's referenced in the [Plugins Go SDK Walkthrough](https://falco.org/docs/plugins/go-sdk-walkthrough/#example-go-plugin-dummy) as an implementation example of a plugin with both event sourcing and field extraction capabilities.

It generates synthetic events and doesn't serve any purpose other than for documentation.

## Event Source

The event source for dummy events is `dummy`.

## Supported Fields

Here is the current set of supported fields:

<!-- README-PLUGIN-FIELDS -->
|       NAME        |   TYPE   |       ARG       |                               DESCRIPTION                               |
|-------------------|----------|-----------------|-------------------------------------------------------------------------|
| `dummy.divisible` | `uint64` | Index, Required | Return 1 if the value is divisible by the provided divisor, 0 otherwise |
| `dummy.value`     | `uint64` | None            | The sample value in the event                                           |
| `dummy.strvalue`  | `string` | None            | The sample value in the event, as a string                              |
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

The format of the open params string is a json object. Here's an example:

```json
{"start": 1, "maxEvents": 20}
```

The json object has the following properties:
* `start`: denotes the initial value of the sample
* `maxEvents`: denotes the number of events to return before returning EOF.

The open params string can be the empty string, which is treated identically to `{}`.

### Run with Falco

Here is a complete `falco.yaml` snippet showing valid configurations for the dummy plugin:

```yaml
plugins:
  - name: dummy
    library_path: libdummy.so
    init_config: '{"jitter": 10}'
    open_params: '{"start": 1, "maxEvents": 20}'

# Optional. If not specified the first entry in plugins is used.
load_plugins: [dummy]
```

Run Falco using `dummy_rules.yaml`

```bash
sudo ./usr/bin/falco -c falco.yaml -r dummy_rules.yaml --disable-source=syscall
```
