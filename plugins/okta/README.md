# Okta Events Plugin

This repository contains the `okta` plugin for `Falco`, which fetch log events from Okta and emit sinsp/scap events (e.g. the events used by `Falco`) for each entry.

The plugin also exports fields that extract information from a `okta` log event, such as the event time, the event type, the actor name, the application, ...

- [Okta Events Plugin](#okta-events-plugin)
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

The event source for `okta` events is `okta`.

# Supported Fields

<!-- README-PLUGIN-FIELDS -->
|              NAME               |   TYPE   | LIST |           DESCRIPTION           |
|---------------------------------|----------|------|---------------------------------|
| `okta.app`                      | `string` | No   | Application                     |
| `okta.evt.type`                 | `string` | No   | Event Type                      |
| `okta.evt.legacytype`           | `string` | No   | Event Legacy Type               |
| `okta.severity`                 | `string` | No   | Severity                        |
| `okta.message`                  | `string` | No   | Message                         |
| `okta.actor.id`                 | `string` | No   | Actor ID                        |
| `okta.actor.Type`               | `string` | No   | Actor Type                      |
| `okta.actor.alternateid`        | `string` | No   | Actor Alternate ID              |
| `okta.actor.name`               | `string` | No   | Actor Display Name              |
| `okta.client.zone`              | `string` | No   | Client Zone                     |
| `okta.client.ip`                | `string` | No   | Client IP Address               |
| `okta.client.device`            | `string` | No   | Client Device                   |
| `okta.client.id`                | `string` | No   | Client ID                       |
| `okta.client.geo.city`          | `string` | No   | Client Geographical City        |
| `okta.client.geo.state`         | `string` | No   | Client Geographical State       |
| `okta.client.geo.country`       | `string` | No   | Client Geographical Country     |
| `okta.client.geo.postalcode`    | `string` | No   | Client Geographical Postal Code |
| `okta.client.geo.lat`           | `string` | No   | Client Geographical Latitude    |
| `okta.client.geo.lon`           | `string` | No   | Client Geographical Longitude   |
| `okta.useragent.os`             | `string` | No   | Useragent OS                    |
| `okta.useragent.browser`        | `string` | No   | Useragent Browser               |
| `okta.useragent.raw`            | `string` | No   | Raw Useragent                   |
| `okta.result`                   | `string` | No   | Outcome Result                  |
| `okta.reason`                   | `string` | No   | Outcome Reason                  |
| `okta.transaction.id`           | `string` | No   | Transaction ID                  |
| `okta.transaction.type`         | `string` | No   | Transaction Type                |
| `okta.requesturi`               | `string` | No   | Request URI                     |
| `okta.principal.id`             | `string` | No   | Principal ID                    |
| `okta.principal.alternateid`    | `string` | No   | Principal Alternate ID          |
| `okta.principal.type`           | `string` | No   | Principal Type                  |
| `okta.principal.name`           | `string` | No   | Principal Name                  |
| `okta.authentication.step`      | `string` | No   | Authentication Step             |
| `okta.authentication.sessionid` | `string` | No   | External Session ID             |
| `okta.security.asnumber`        | `uint64` | No   | Security AS Number              |
| `okta.security.asorg`           | `string` | No   | Security AS Org                 |
| `okta.security.isp`             | `string` | No   | Security ISP                    |
| `okta.security.domain`          | `string` | No   | Security Domain                 |
| `okta.target.user.id`           | `string` | No   | Target User ID                  |
| `okta.target.user.aternateid`   | `string` | No   | Target User Alternate ID        |
| `okta.target.user.name`         | `string` | No   | Target User Name                |
| `okta.target.group.id`          | `string` | No   | Target Group ID                 |
| `okta.target.group.aternateid`  | `string` | No   | Target Group Alternate ID       |
| `okta.target.group.name`        | `string` | No   | Target Group Name               |
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
* `organization`: the name of your organization (same as in *https://xxxx.okta.com*)
* `api_token`: your API Token to access Okta API

# Configurations

* `falco.yaml`

  ```yaml
  plugins:
    - name: okta
      library_path: /usr/share/falco/plugins/libokta.so
      init_config:
        organization: myorg
        api_token: xxxxxxxxxxx
      open_params: ''

  load_plugins: [okta]
  ```

* `rules.yaml`

The `source` for rules must be `okta`.

See example:
```yaml
- rule: Dummy
  desc: Dummy
  condition: okta.app!="" 
  output: "evt=%okta.evt.type user=%okta.actor.name ip=%okta.client.ip app=%okta.app"
  priority: DEBUG
  source: okta
  tags: [okta]
```

# Usage

```shell
falco -c falco.yaml -r okta_rules.yaml
```

## Requirements

* `Falco` >= 0.31

## Results

```shell
19:12:25.439350000: Debug evt=user.authentication.sso user=User1 ip=x.x.x.x app=google
19:12:30.675628000: Debug evt=user.authentication.sso user=User2 ip=x.x.x.x app=github
19:12:35.918456000: Debug evt=user.authentication.sso user=User3 ip=x.x.x.x app=office365
```