This directory contains the C++ Plugin SDK, in the form of a C++ header file. The header file declares two abstract base classes:

* `falcosecurity::source_plugin`: implements the interface to the plugin framework for a source plugin. Plugin authors can derive from this base class and implement the abstract methods to identify a plugin and extract fields.
* `falcosecurity::plugin_instance`: implements the interface to the plugin framework for a plugin instance (e.g. open stream of events). Plugins authors use this base class and implement methods to return events to the plugin framework.

For more information on use of this sdk, see the reference [dummy_c](../../plugins/dummy_c) plugin as well as the plugin [developer's guide](https://deploy-preview-493--falcosecurity.netlify.app/docs/plugins/developers_guide/).
