### Registering a Plugin

Registering your plugin inside the registry helps ensure that some technical constraints are respected, such as that a [given ID is used by exactly one plugin with event source capability](https://falco.org/docs/concepts/plugins/architecture/#plugin-event-ids) and allows plugin authors to [coordinate about event source formats](https://falco.org/docs/concepts/plugins/architecture/#plugin-event-sources-and-interoperability). Moreover, this is a great way to share your plugin project with the community and engage with it, thus gaining new users and **increasing its visibility**. We encourage you to register your plugin in this registry before publishing it. You can add your plugins in this registry regardless of where its source code is hosted (there's a `url` field for this specifically).

The registration process involves adding an entry about your plugin inside the [registry.yaml](../registry.yaml) file by creating a Pull Request in this repository. Please be mindful of a few constraints that are automatically checked and required for your plugin to be accepted:

- The `name` field is mandatory and must be **unique** across all the plugins in the registry
- *(Sourcing Capability Only)* The `id` field is mandatory and must be **unique** in the registry across all the plugins with event source capability
  - See [docs/plugin-ids.md](plugin-ids.md) for more information about plugin IDs
- The plugin `name` must match this [regular expression](https://en.wikipedia.org/wiki/Regular_expression): `^[a-z]+[a-z0-9-_\-]*$` (however, its not recommended to use `_` in the name, unless you are trying to match the name of a source or for particular reasons)
- The `source` *(Sourcing Capability Only)* and `sources` *(Extraction Capability Only)* must match this [regular expression](https://en.wikipedia.org/wiki/Regular_expression): `^[a-z]+[a-z0-9_]*$`
- The `url` field should point to the plugin source code
- The `rules_url` field should point to the default ruleset, if any

For reference, here's an example of an entry for a plugin with both event sourcing and field extraction capabilities:
```yaml
- name: k8saudit
  description: ...
  authors: ...
  contact: ...
  maintainers:
    - name: The Falco Authors
      email: cncf-falco-dev@lists.cncf.io
  keywords:
    - audit
    - audit-log
    - audit-events
    - kubernetes
    url: https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit
    rules_url: https://github.com/falcosecurity/plugins/tree/main/plugins/k8saudit/rules
  url: ...
  license: ...
  capabilities:
    sourcing:
      supported: true
      id: 2
      source: k8s_audit
    extraction:
      supported: true
```