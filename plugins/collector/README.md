# Falco Collector Plugin


The `collector` is a generic [Falco](https://falco.org) source plugin that listens for incoming HTTP POST requests and ingests the raw payloads as events. This plugin is designed for use cases where external components (e.g. other Falco instances, alerting systems, or webhooks) need to push data into the Falco engine for further processing.

This plugin **does not expose any fields** on its own. Instead, it is intended to be used in **conjunction with a parser plugin** such as [`json`](https://github.com/falcosecurity/plugins/tree/main/plugins/json), which can extract structured data from the raw payloads in case of JSON formatted data.

## Example Use Case

You can deploy the collector plugin alongside the `json` plugin to:

- Ingest alerts or events from remote Falco instances configured to send their output in JSON to the collector endpoint.
- Use Falco rules based on the `json` to filter and analyze those events by parsing the JSON payload.

## Plugin Configuration

The plugin accepts the following configuration parameters as JSON:

```json
{
  "buffer": 0,
  "addr": ":54827"
}
```

| Key      | Type     | Default     | Description                                                                 |
| -------- | -------- | ----------- | --------------------------------------------------------------------------- |
| `buffer` | `uint64` | `0`         | Number of payloads held by the buffer.                                      |
| `addr`   | `string` | `:54827`    | Address for the HTTP server to listen on (e.g., `:8080`, `127.0.0.1:9000`). |

### Example Plugin Load Configuration

When using this plugin in Falco, configure it like this:

```yaml
load_plugins: [collector, json]

plugins:
  - name: collector
    library_path: libcollector.so

  - name: json
    library_path: libjson.so
```

## Example Payload

Send an event to the collector plugin using `curl`:

```bash
curl -X POST http://localhost:54827 -d '{"hostname":"x86","output":"14:50:34.502309868: Warning Sensitive file opened for reading by non-trusted program (file=/etc/shadow gparent=sudo ggparent=zsh gggparent=kitty evt_type=openat user=root user_uid=0 user_loginuid=1000 process=cat proc_exepath=/usr/bin/cat parent=sudo command=cat /etc/shadow terminal=34820 container_id=host container_name=host)","output_fields":{"container.id":"host","container.name":"host","evt.time":1746622234502309868,"evt.type":"openat","fd.name":"/etc/shadow","proc.aname[2]":"sudo","proc.aname[3]":"zsh","proc.aname[4]":"kitty","proc.cmdline":"cat /etc/shadow","proc.exepath":"/usr/bin/cat","proc.name":"cat","proc.pname":"sudo","proc.tty":34820,"user.loginuid":1000,"user.name":"root","user.uid":0},"priority":"Warning","rule":"Read sensitive file untrusted","source":"syscall","tags":["T1555","container","filesystem","host","maturity_stable","mitre_credential_access"],"time":"2025-05-07T12:50:34.502309868Z"}'
```

Then, using the `json` plugin, you can create rules that filter on any of the fields in the JSON payload, for example:

```yaml
- rule: Non-container event
  desc: Match host events from a JSON-formatted Falco alert for syscall source.
  condition: json.value[/output_fields/container.id] == "host"
  output: Non-container event (payload=%evt.plugininfo)
  priority: INFO
  source: collector
```