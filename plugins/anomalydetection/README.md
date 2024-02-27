# Falcosecurity `anomalydetection` Plugin

This `anomalydetection` plugin has been created upon this [Proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20230620-anomaly-detection-framework.md).

## Introduction

The `anomalydetection` plugin enhances {syscall} event analysis by incorporating anomaly detection estimates for probabilistic filtering.

### Functionality

The initial scope will focus exclusively on "CountMinSketch Powered Probabilistic Counting and Filtering" for a subset of syscalls and a selection of options to define behavior profiles. The primary objective of this new framework is to offer tangible advantages in real-world production environments and substantially improve the usability of standard Falco rules. Essentially, this framework eliminates the requirement for meticulous tuning of individual rules and facilitates the utilization of probabilistic count estimates to alleviate the impact of noisy rules. Additionally, it enables the creation of broader Falco rules. Read more in the [Proposal](https://github.com/falcosecurity/falco/blob/master/proposals/20230620-anomaly-detection-framework.md).

### Plugin Official Name

`anomalydetection`

## Capabilities

The `anomalydetection` plugin implements 2 capabilities:

* `extraction`
* `parsing`

## Supported Fields

Here is the current set of supported fields:

<!-- README-PLUGIN-FIELDS -->
|       NAME        |   TYPE   |       ARG       |                               DESCRIPTION                               |
|-------------------|----------|-----------------|-------------------------------------------------------------------------|
| `anomalydetection.count_min_sketch` | `uint64` | Key, Optional | Count Min Sketch Estimate according to the specified behavior profile for a predefined set of {syscalls} events. Access different behavior profiles/sketches using indices. For instance, anomalydetection.count_min_sketch[0] retrieves the first behavior profile defined in the plugins' `init_config`. |
<!-- /README-PLUGIN-FIELDS -->

## Usage

### Configuration

Here's an example of configuration of `falco.yaml`:

```yaml
plugins:
  - name: anomalydetection
    library_path: libanomalydetection.so
    init_config:
      n_sketches: 3

load_plugins: [anomalydetection]
```

**Open Parameters**:

This plugin does not have open params.

**Rules**

This plugin does not provide any custom rules. You can use the default Falco ruleset and add the necessary `anomalydetection` fields as output fields to obtain the Count Min Sketch estimates and/or use them in the familiar rules filter condition.

Example of a standard Falco rule using the `anomalydetection` fields:

```yaml
- macro: spawned_process
  condition: (evt.type in (execve, execveat) and evt.dir=<)
- rule: execve count_min_sketch test
  desc: "execve count_min_sketch test"
  condition: spawned_process and proc.name=cat and anomalydetection.count_min_sketch > 10
  output: '%anomalydetection.count_min_sketch %proc.pid %proc.ppid %proc.name %user.loginuid %user.name %user.uid %proc.cmdline %container.id %evt.type %evt.res %proc.cwd %proc.sid %proc.exepath %container.image.repository'
  priority: NOTICE
  tags: [maturity_sandbox, host, container, process, anomalydetection]
```

__NOTE__: Ensure you regularly execute `cat` commands. Once you have done so frequently enough, logs will start to appear. Alternatively, perform an inverse test to observe how quickly a very noisy rule gets silenced.

### Running

This plugin requires Falco with version >= **0.37.0**.
Modify the `falco.yaml` with the provided [configuration](#configuration) above and you are ready to go!

```shell
sudo falco -c falco.yaml -r falco_rules.yaml
```

## Local Development

### Build

```bash
git clone https://github.com/falcosecurity/plugins.git
cd plugins/anomalydetection
rm -f libanomalydetection.so; 
rm -f build/libanomalydetection.so; 
make;
# Copy the shared library to the expected location for `falco.yaml`, which is `library_path: libanomalydetection.so`
sudo mkdir -p /usr/share/falco/plugins/;
sudo cp -f libanomalydetection.so /usr/share/falco/plugins/libanomalydetection.so;
```
