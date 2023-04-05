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
| NAME                            |   TYPE   |       ARG       | DESCRIPTION                           |
|---------------------------------|----------|-----------------|---------------------------------------|
| `okta.app`                      | `string` | None            | Application                           |
| `okta.org`                      | `string` | None            | Organization                          |
| `okta.evt.type`                 | `string` | None            | Event Type                            |
| `okta.evt.legacytype`           | `string` | None            | Event Legacy Type                     |
| `okta.severity`                 | `string` | None            | Severity                              |
| `okta.message`                  | `string` | None            | Message                               |
| `okta.published`                | `string` | None            | Event Source Timestamp                |
| `okta.actor.id`                 | `string` | None            | Actor ID                              |
| `okta.actor.Type`               | `string` | None            | Actor Type                            |
| `okta.actor.alternateid`        | `string` | None            | Actor Alternate ID                    |
| `okta.actor.name`               | `string` | None            | Actor Display Name                    |
| `okta.client.zone`              | `string` | None            | Client Zone                           |
| `okta.client.ip`                | `string` | None            | Client IP Address                     |
| `okta.client.device`            | `string` | None            | Client Device                         |
| `okta.client.id`                | `string` | None            | Client ID                             |
| `okta.client.geo.city`          | `string` | None            | Client Geographical City              |
| `okta.client.geo.state`         | `string` | None            | Client Geographical State             |
| `okta.client.geo.country`       | `string` | None            | Client Geographical Country           |
| `okta.client.geo.postalcode`    | `string` | None            | Client Geographical Postal Code       |
| `okta.client.geo.lat`           | `string` | None            | Client Geographical Latitude          |
| `okta.client.geo.lon`           | `string` | None            | Client Geographical Longitude         |
| `okta.useragent.os`             | `string` | None            | Useragent OS                          |
| `okta.useragent.browser`        | `string` | None            | Useragent Browser                     |
| `okta.useragent.raw`            | `string` | None            | Raw Useragent                         |
| `okta.result`                   | `string` | None            | Outcome Result                        |
| `okta.reason`                   | `string` | None            | Outcome Reason                        |
| `okta.transaction.id`           | `string` | None            | Transaction ID                        |
| `okta.transaction.type`         | `string` | None            | Transaction Type                      |
| `okta.requesturi`               | `string` | None            | Request URI                           |
| `okta.principal.id`             | `string` | None            | Principal ID                          |
| `okta.principal.alternateid`    | `string` | None            | Principal Alternate ID                |
| `okta.principal.type`           | `string` | None            | Principal Type                        |
| `okta.principal.name`           | `string` | None            | Principal Name                        |
| `okta.authentication.step`      | `string` | None            | Authentication Step                   |
| `okta.authentication.sessionid` | `string` | None            | External Session ID                   |
| `okta.security.asnumber`        | `uint64` | None            | Security AS Number                    |
| `okta.security.asorg`           | `string` | None            | Security AS Org                       |
| `okta.security.isp`             | `string` | None            | Security ISP                          |
| `okta.security.domain`          | `string` | None            | Security Domain                       |
| `okta.target.user.id`           | `string` | None            | Target User ID                        |
| `okta.target.user.alternateid`  | `string` | None            | Target User Alternate ID              |
| `okta.target.user.name`         | `string` | None            | Target User Name                      |
| `okta.target.group.id`          | `string` | None            | Target Group ID                       |
| `okta.target.group.alternateid` | `string` | None            | Target Group Alternate ID             |
| `okta.target.group.name`        | `string` | None            | Target Group Name                     |
| `okta.mfa.failure.countlast`    | `uint64` | Index, Required | Count of MFA failures in last seconds |
| `okta.mfa.deny.countlast`       | `uint64` | Index, Required | Count of MFA denies in last seconds   |
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
* `cache_expiration`: TTL in seconds for keys in cache for MFA events (default: 600)
* `cache_usermaxsize`: Max size by user for the cache (default: 200)

# Configurations

* `falco.yaml`

  ```yaml
  plugins:
    - name: okta
      library_path: /usr/share/falco/plugins/libokta.so
      init_config:
        organization: myorg
        api_token: xxxxxxxxxxx
        cache_expiration: 84600 #24h
        cache_usermaxsize: 200
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
