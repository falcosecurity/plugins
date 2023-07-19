# GCP audit logs Events Plugin

This GCP Audit Logs Plugin is designed to ingest GCP audit logs for several GCP services, including Compute Engine, KMS, Cloud Armor WAF, IAM, Firewall, Cloud Storage, BigQuery, CloudSQL, Pub/Sub, Cloud Logging, and Cloud Functions.

The GCP Audit Logs Plugin's primary purpose is to detect security threats, vulnerabilities, and compliance risks by analyzing the ingested GCP audit logs. The default security detection rules were built with the MITRE & ATT&CK framework in mind, which provides a comprehensive and industry-standard way to identify and classify different types of security threats.

The GCP Audit Logs Plugin can help security teams identify and respond to security incidents quickly, improve compliance posture, and reduce overall risk to the organization. It provides a comprehensive and centralized view of security events across multiple GCP services and can help detect and prevent unauthorized access, data exfiltration, and other types of malicious activity.

By leveraging GCP audit logs, the GCP Audit Logs Plugin provides deep insights into the activities of different users, services, and resources in your GCP environment. The GCP Audit Logs Plugin's advanced ebpf capabilities enable it to identify anomalous activities and raise alerts when it detects suspicious or malicious behavior.

The GCP Audit Logs Plugin also offers customizable detection rules that enable you to fine-tune the detection capabilities to suit your organization's specific needs. You can customize the rules to detect specific types of security threats, monitor specific users or services, and track specific resources or data types.


For more details about what GCP Audit logs are, see the [GCP official documentation](https://cloud.google.com/logging/docs/audit/understanding-audit-logs).

### Functionality

The GCP Audit Logs Plugin comes with pre-built security detection rules designed to detect security threats based on the MITRE & ATT&CK framework. These rules are constantly updated to ensure that the security agent is always detecting the latest threats and vulnerabilities.

The default security detection rules cover the following areas:

* Identity and Access Management (IAM)
* Network Security
* Data Security
* Compliance
* Infrastructure Security
* Cloud Service Providers

The GCP Audit Logs Plugin's detection rules can identify threats such as:

* Privilege escalation
* Unauthorized access
* Data exfiltration
* Denial of Service (DoS) attacks
* Insider threats
* Suspicious network activity

- [GCP Audit Logs Plugin](#GCP Audit Logs Plugin)
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

The event source for `GCP Audit Logs Plugin` events is `GCP Audit Logs`.

This GCP Audit Logs Plugin is designed to ingest GCP audit logs from several GCP services, including: 
* Compute Engine
* KMS 
* Cloud Armor WAF 
* IAM 
* Firewall 
* Cloud Storage
* BigQuery
* Cloud SQL
* Pub/Sub
* Cloud Logging
* Cloud Functions

The GCP Audit Logs Plugin subscribes to a Pub/Sub topic service and is backed by an optimized sink that exports the most important log entries.

```sql
log_name="projects/your-gcp-project-id/logs/cloudaudit.googleapis.com%2Factivity" AND
(protoPayload.serviceName="cloudsql.googleapis.com" OR 
protoPayload.serviceName="logging.googleapis.com" OR 
protoPayload.serviceName="iam.googleapis.com" OR 
(protoPayload.serviceName="compute.googleapis.com" AND NOT protoPayload.authenticationInfo.principalEmail=~"^service-") OR 
protoPayload.serviceName="pubsub.googleapis.com" OR
protoPayload.serviceName="cloudkms.googleapis.com" OR
protoPayload.serviceName="cloudfunctions.googleapis.com" OR
protoPayload.serviceName="storage.googleapis.com" OR
protoPayload.serviceName="cloudresourcemanager.googleapis.com" OR
protoPayload.serviceName="bigquery.googleapis.com")
```

You can change the log query to fit your specific needs.

For more details about what Cloud logging log queries, see the [GCP official documentation](https://cloud.google.com/logging/docs/view/logging-query-language).

# Supported Fields

<!-- README-PLUGIN-FIELDS -->
|          NAME           |   TYPE   | ARG  |                   DESCRIPTION                   |
|-------------------------|----------|------|-------------------------------------------------|
| `gcp.user`              | `string` | None | GCP principal email who committed the action    |
| `gcp.callerIP`          | `string` | None | GCP principal caller IP                         |
| `gcp.userAgent`         | `string` | None | GCP principal caller useragent                  |
| `gcp.authorizationInfo` | `string` | None | GCP authorization information affected resource |
| `gcp.serviceName`       | `string` | None | GCP API service name                            |
| `gcp.policyDelta`       | `string` | None | GCP service resource access policy              |
| `gcp.request`           | `string` | None | GCP API raw request                             |
| `gcp.methodName`        | `string` | None | GCP API service  method executed                |
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
* `project_id`: the name of your GCP project
* `num_goroutines`: is the number of goroutines that each datastructure along the Receive path will spawn (default: 10)
* `maxout_stand_messages`: is the maximum number of unprocessed messages (default: 1000)
* `sub_id`: The subscriber name for your pub/sub topic

# Configurations

* `falco.yaml`

  ```yaml
  plugins:
    - name: json
      library_path: libjson.so

    - name: gcpaudit
      library_path: libgcpaudit.so
      init_config: '{"num_goroutines": 4, "maxout_stand_messages": 100, "project_id": "your-gcp-project", "sub_id":"Your-subscription-ID"}'
  load_plugins: [gcpaudit, json]
  ```

* `rules.yaml`

The `source` for rules must be `gcp_auditlog`.

See example:
```yaml
- rule: GCP Bucket configured to be public
  desc: Detect when access on a GCP Bucket granted to the public internet.
  condition: is_gcs_service and gcp.methodName="storage.setIamPermissions" and is_binded_delta_to_public 
  output: > 
    project=%json.value[/resource/labels/project_id]
    A GCP bucket access granted to be public by user=%gcp.user userIP=%gcp.callerIP userAgent=%gcp.userAgent  bindedDelta=%gcp.policyDelta
    authorizationInfo=%gcp.authorizationInfo
    rawRequest=%gcp.request 
    bucketName=%json.value[/resource/labels/bucket_name]  
  priority: CRITICAL
  source: auditlogs
  tags: [GCP, buckets, compliance]
```

# Usage

```shell
falco -c falco.yaml -r auditlogs_rules.yaml
```

## Requirements

* `Falco` >= 0.35

## Results

```shell
{"hostname":"sherlock","output":"01:43:54.476694000: Notice project=********** A GCP WAF network policy or waf rule modified by user=ahmed.amin@test.com userIP=41.45.115.69 userAgent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)  authorizationInfo=[{\"granted\":true,\"permission\":\"compute.securityPolicies.update\",\"resourceAttributes\":{\"name\":\"projects/=**********/global/securityPolicies/**********\",\"service\":\"compute\",\"type\":\"compute.securityPolicies\"}}] rawRequest={\"@type\":\"type.googleapis.com/compute.securityPolicies.addRule\",\"action\":\"deny(403)\",\"description\":\"\",\"match\":{\"config\":{\"srcIpRanges\":[\"1.1.1.1\"]},\"versionedExpr\":\"SRC_IPS_V1\"},\"preview\":false,\"priority\":\"0\"} policyName=**********","priority":"Notice","rule":"GCP WAF rule modified or deleted","source":"gcp_auditlog","tags":["CloudArmor","GCP","T1562-impair-defenses","TA0005-defense-evasion","WAF"],"time":"2023-07-06T22:43:54.476694000Z", "output_fields": {"evt.time":1688683434476694000,"gcp.authorizationInfo":"[{\"granted\":true,\"permission\":\"compute.securityPolicies.update\",\"resourceAttributes\":{\"name\":\"projects/=**********/global/securityPolicies/**********\",\"service\":\"compute\",\"type\":\"compute.securityPolicies\"}}]","gcp.callerIP":"41.45.115.69","gcp.request":"{\"@type\":\"type.googleapis.com/compute.securityPolicies.addRule\",\"action\":\"deny(403)\",\"description\":\"\",\"match\":{\"config\":{\"srcIpRanges\":[\"1.1.1.1\"]},\"versionedExpr\":\"SRC_IPS_V1\"},\"preview\":false,\"priority\":\"0\"}","gcp.user":"ahmed.amin@test.com","gcp.userAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)","json.value[/resource/labels/policy_name]":"**********","json.value[/resource/labels/project_id]":"****"}}

{"hostname":"sherlock","output":"03:36:21.780289000: Critical project=********** A GCP bucket access granted to be public by user=ahmed.amin@test.com userIP=156.204.230.94 userAgent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)  bindedDelta=[{\"action\":\"ADD\",\"member\":\"allUsers\",\"role\":\"roles/storage.objectViewer\"}] authorizationInfo=[{\"granted\":true,\"permission\":\"storage.buckets.setIamPolicy\",\"resource\":\"projects/_/buckets/amin-test\",\"resourceAttributes\":{}}]  bucketName=ahmed-test","priority":"Critical","rule":"GCP Bucket configured to be public","source":"gcp_auditlog","tags":["GCP","buckets","compliance"],"time":"2023-06-30T00:36:21.780289000Z", "output_fields": {"evt.time":1688085381780289000,"gcp.authorizationInfo":"[{\"granted\":true,\"permission\":\"storage.buckets.setIamPolicy\",\"resource\":\"projects/_/buckets/ahmed-test\",\"resourceAttributes\":{}}]","gcp.callerIP":"156.204.230.94","gcp.policyDelta":"[{\"action\":\"ADD\",\"member\":\"allUsers\",\"role\":\"roles/storage.objectViewer\"}]","gcp.user":"ahmed.amin@test.com","gcp.userAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)","json.value[/resource/labels/bucket_name]":"ahmed-test","json.value[/resource/labels/project_id]":"**********"}}

{"hostname":"sherlock","output":"01:36:49.223570000: Notice project=-***-**-*** A GCP WAF network policy or waf rule modified by user=ahmed.amin@test.com userIP=x.x.x.x userAgent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe) authorizationInfo=[{\"granted\":true,\"permission\":\"compute.securityPolicies.update\",\"resourceAttributes\":{\"name\":\"projects/-***-**-***/global/securityPolicies/xxx-xxxx-xxxx\",\"service\":\"compute\",\"type\":\"compute.securityPolicies\"}}] policyName=xxx-xxxx-xxxx","priority":"Notice","rule":"GCP WAF rule modified or deleted","source":"auditlogs","tags":["CloudArmor","GCP","T1562-impair-defenses","TA0005-defense-evasion","WAF"],"time":"2023-04-22T23:36:49.223570000Z", "output_fields": {"gcp.authorizationInfo ":"[{\"granted\":true,\"permission\":\"compute.securityPolicies.update\",\"resourceAttributes\":{\"name\":\"projects/-***-**-***/global/securityPolicies/xxx-xxxx-xxxx\",\"service\":\"compute\",\"type\":\"compute.securityPolicies\"}}]","gcp.user":"ahmed.amin@test.com","al.principal.ip":"x.x.x.x","gcp.userAgent ":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36,gzip(gfe),gzip(gfe)","evt.time":1682206609223570000,"json.value[/resource/labels/policy_name]":"xxx-xxxx-xxxx","json.value[/resource/labels/project_id]":"-***-**-***"}}

{"hostname":"sherlock-ThinkBook-15-G2-ITL","output":"02:48:23.599777000: Notice project=xxx-xxxx-xxxx A GCP serviceAccount delete by user=ahmed.amin@test.com userIP=156.204.230.94 userAgent=Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe)  authorizationInfo=[{\"granted\":true,\"permission\":\"iam.serviceAccounts.delete\",\"resource\":\"projects/-/serviceAccounts/101363364166838521279\",\"resourceAttributes\":{\"name\":\"projects/-/serviceAccounts/101363364166838521279\"}}]","priority":"Notice","rule":"GCP IAM serviceAccount deleted","source":"gcp_auditlog","tags":["GCP","IAM","abuse-elevation-control-mechanism"],"time":"2023-06-29T23:48:23.599777000Z", "output_fields": {"evt.time":1688082503599777000,"gcp.authorizationInfo":"[{\"granted\":true,\"permission\":\"iam.serviceAccounts.delete\",\"resource\":\"projects/-/serviceAccounts/101363364166838521279\",\"resourceAttributes\":{\"name\":\"projects/-/serviceAccounts/101363364166838521279\"}}]","gcp.callerIP":"156.204.230.94","gcp.user":"ahmed.amin@test.com","gcp.userAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36,gzip(gfe)","json.value[/resource/labels/project_id]":"xxx-xxxx-xxxx"}}


```
