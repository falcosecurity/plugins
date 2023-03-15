# Best Practices  aaa test

This page summarizes some best practices and guidelines that can be useful to developers that are getting started with the [plugin system of Falco](https://falco.org/docs/plugins/). The [Developers Guide](https://falco.org/docs/plugins/developers-guide/) is mostly focused on the technical aspects of plugin development. In contrast, here we provide some guidance on more high-level points that may occur during the design and implementation phases.

## Plugin Directory Structure

Currently, Go is the most used language for writing plugins. So, below you can find the recommended layout for Go plugin projects. For other languages, you can adapt the layout accordingly. 

### `/pkg`

Reusable Go packages that other plugins or projects can use. This directory is not mandatory but is highly recommended.

### `/plugin`

This directory contains the plugin entry point. This directory should have only one `.go` file, named as your plugin. This file must define the `main` package (and an empty `main()` function) per CGO requirement. 
Usually, this file also imports packages from `/pkg` and defines an `init()` function to register the plugin capabilities (that's required if you are using the [plugin-go-sdk](https://github.com/falcosecurity/plugin-sdk-go)).

### `/rules`

This directory is optional. If you want to distribute rules files for your plugin, you can put them in this directory.
The building system of this repository will automatically build and publish them as a `.tar.gz` archive under [https://download.falco.org/?prefix=plugins/](https://download.falco.org/?prefix=plugins/).

### `/Makefile`

Providing a `Makefile` is mandatory for plugins hosted by this repository. The building system of this repository will use:
- `make` to build the plugin binary
- `make clean` to clean the built artifacts
- `make rules` to build the rules files (this is optional)

Below you can find an example of a typical `Makefile` for a plugin hosted by this repository.

```Makefile
SHELL=/bin/bash -o pipefail
GO ?= go

NAME := <YOUR-PLUGIN-NAME-HERE>
OUTPUT := lib$(NAME).so

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=2
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: $(OUTPUT)

clean:
	@rm -f *.so *.h

$(OUTPUT):
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT) ./plugin
```

## Configuration in Source Plugins

One peculiarity of plugins with event source capability is how they can accept user configurations. Other plugins can only be configured during the initialization phase through `plugin_init()`, whereas source plugins also take some parameters while opening the event stream with `plugin_open()`. This creates some ambiguity on **which** information should go inside the init configuration and what should be part of the open parameters instead.

There's no silver bullet for this problem, and the solution strictly depends on the use cases of your plugin. However, there are some principles you can follow.

- The [init configuration](https://falco.org/docs/configuration/#plugins) should contain information that is used during the whole plugin lifecycle and that is used across both field extraction and event generation
- The init configuration is the right place for structured data. In fact, in most cases, plugins accept JSON strings as a configuration and also expose a schema describing/documenting the expected data format (see [`plugin_get_init_schema`](https://falco.org/docs/plugins/plugin-api-reference/#get-init-schema) for more details)
- Init configuration parameters should have the following annotations. See the [JSON Schema Validation specification](https://json-schema.org/draft/2020-12/json-schema-validation.html#name-a-vocabulary-for-basic-meta) for more details:
    - `title`, which provides a short user-facing name for the parameter.
    - `description`, which describes the parameter using a sentence or a short paragraph.
    - `default` (optional), which provides the default value of the parameter.
    - `required` (optional), which notes that the parameter value is required.
    - `examples` (optional), which provides example values for the parameter.
- The open parameters should contain information that is only relevant for opening a specific event source, and their lifecycle ends at the invocation of `plugin_close()`
- The open parameters should contain minimal and non-structured information, such as a URI or a resource descriptor string. This is the reason why the framework does not support any schema definition for open parameters and treats them as an opaque string. Ideally, if more than one parameter is required to open a data source, comma-separated string concatenation is preferable to structured data formats such as JSON

## Secret Management

An important decision during plugin development is how secrets are managed. It's common to manage connections to external services, authenticate with credentials, or use private tokens. Plugins accept user-defined values only through the [init configuration](https://falco.org/docs/configuration/#plugins) or the open parameters. In general, you shouldn't pass secrets directly inside the init configuration or the open parameters. Instead, there are a few guidelines you can follow in order to ensure that your secrets are managed safely in the plugin framework.

### Don't

- Pass credentials or secrets in the plugin:
    - Init configuration
    - Open parameters
- Create custom conventions (e.g. storing the secrets in a non-customizable path such as `~/.mysecrets`)
- Embed credentials or secrets inside the plugin code

### Do

- Retrieve credentials or secrets through environment variables or external files, and pass their name in the plugin:
    - Init configuration
    - Open parameters, only if they are required to open the event source
- Follow the secret management guidelines mandated by well-known packages such as [aws-sdk-go](https://github.com/aws/aws-sdk-go#configuring-credentials)


## Managing the NextBatch Loop

In source plugins, new events are created and returned in batches with the `plugin_next_batch()` function. This design decision reduces the overhead that may occur by integrating C with other programming languages such as Go. Although the SDKs cover most of the hard work, plugin developers must manage the batching system manually and there are some things to keep in mind to ensure optimal performance and correct behavior.

### Don't

- Allocate a new event batch at every invocation of `plugin_next_batch()`, because event generation is a very hot path
- Block the execution for long times: be mindful that `plugin_next_batch()` is blocking for the framework
- Return an EOF error and then return new events at the following invocation of `plugin_next_batch()`
- Return a given number of events without filling their data in the event batch

### Do

- Rely on the Go SDK and C++ SDK to ensure that all memory allocations are optimized
- Return a number of events smaller than the size of the batch, if fastly available (see the behavior described [in the Go SDK](https://pkg.go.dev/github.com/falcosecurity/plugin-sdk-go@v0.1.0/pkg/sdk#NextBatcher))
- Return Timeout (see [`sdk.ErrTimeout`](https://github.com/falcosecurity/plugin-sdk-go/blob/0b4b6dc215141116c53398f3232aac98e49cdb80/pkg/sdk/sdk.go#L30) in Go or [`SS_PLUGIN_TIMEOUT`](https://github.com/falcosecurity/libs/blob/033c4b9f28e58e20a5822bd8a7419beea098af91/userspace/libscap/plugin_info.h#L76) in C/C++) after a short time period passes without producing any event (no more than a few milliseconds)
- Return Timeout even with a non-zero number of events, if they are available
- Return EOF (see [`sdk.ErrEOF`](https://github.com/falcosecurity/plugin-sdk-go/blob/0b4b6dc215141116c53398f3232aac98e49cdb80/pkg/sdk/sdk.go#L25) in Go or [`SS_PLUGIN_EOF`](https://github.com/falcosecurity/libs/blob/033c4b9f28e58e20a5822bd8a7419beea098af91/userspace/libscap/plugin_info.h#L77) in C/C++) when you are certain that no more events will be produced
- Return EOF with a non-zero number of events, but ensuring that every following invocation of `plugin_next_batch()` returns EOF and zero events


## Fields Naming Conventions

Plugins can extend Falco by supporting new fields to be extracted event data. At runtime, those fields co-exist with the other fields natively supported in libsinsp, such as the `evt.*` or the `container.*` classes. In this perspective, it's really important for plugin developers to follow some naming conventions for the newly introduced fields.

### Don't

- Introduce fields with the same name or the same class (e.g. `evt.*`, `container.*`, `ka.*`) as the ones already existing in libsinsp
- Use field names containing arbitrary characters
- Assign unnecessarely long names to your fields

### Do

- Make sure your fields have an unique-ish class prefix that represents the use case of your plugin (e.g. `ct.*` for AWS Cloudtrail). This will help avoid ambiguities for rulesets using your fields in rule conditions
- Use field names matching the following safe regular expression, that is compliant with the grammar of the rule parser: `[a-z]+[a-z0-9_]*(\.[a-z]+[a-z0-9_]*)+`
- Use the `.` divisor character to give better meaning to your fields and divide them into categories (e.g. `ct.user.accountid` refers to the `user` category of AWS Cloudtrail events)


## Live Events vs. Offline Events

Once you get started developing a source plugin, you may come to the conclusion that there is absolutely no technical constraint on the events returned with `plugin_next_batch()`, since the plugin dictates both the data format of the events and how frequently they are produced. Some many degrees of freedom can be confusing and can make developer wonder to which extent the behavior of Falco should be changed.

An important topic is the difference between producing events from a *live* or *offline* source. Those two terms are meant to distinguish events produced in real-time from the ones generated by parsing a static and reproducible source (such as a log file). In other words, live events are not reproducible because they are tied to real-time observations. To clear some of these doubts, be mindful of the following points:

- Falco has been designed as a tool for runtime security, and it is supposed to stay in that space as much as possible
- By default, plugins are meant to always produce live events
- Plugins can **optionally** produce offline events with a given configuration or with special open parameters. This is helpful to satisfy use cases involving debugging, testing, and reproducibility
- Live events do not include events that happened before the plugin startup. For instance, assuming one has a log file:
    - `tail -f` would output live events only
    - `cat` would output all events (ie. offline mode)
