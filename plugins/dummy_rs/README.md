# Falcosecurity dummy_rs Plugin

This directory contains the dummy_rs plugin, which is an example plugin written in Rust. Take a look at the [plugin-sdk-rs](https://github.com/falcosecurity/plugin-sdk-rs) to find out more about the writing plugins in Rust.

It generates synthetic events and doesn't serve any purpose other than for documentation.

It is a companion to the `dummy` plugin which is written in Go but supports the same fields, event source, and configuration.

## Event Source

The event source for dummy events is `dummy_rs`.

## Supported Fields

Here is the current set of supported fields:

<!-- README-PLUGIN-FIELDS -->
|       NAME        |   TYPE   |       ARG       |                               DESCRIPTION                               |
|-------------------|----------|-----------------|-------------------------------------------------------------------------|
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

Here is a complete `falco.yaml` snippet showing valid configurations for the `dummy_rs` plugin:

```yaml
plugins:
  - name: dummy_rs
    library_path: libdummy_rs.so
    init_config: '{"jitter": 10}'
    open_params: '{"start": 1, "maxEvents": 20}'

# Optional. If not specified the first entry in plugins is used.
load_plugins: [dummy_rs]
```

Run Falco using `dummy_rs_rules.yaml`

```bash
sudo ./usr/bin/falco -c falco.yaml -r dummy_rs_rules.yaml --disable-source=syscall
```
