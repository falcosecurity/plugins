# GCP Audit Logs Plugin (Rust)

This is a Rust translation of the GCP Audit Logs Plugin for Falco. It ingests GCP audit logs from Google Cloud Pub/Sub and extracts security-relevant fields for threat detection.

## Features

- **Event Source**: Subscribes to GCP Pub/Sub topics to receive audit log events
- **Field Extraction**: Extracts 25+ fields from GCP audit logs including:
  - User information (email, IP, user agent)
  - Resource details (project ID, resource type, labels)
  - Service-specific fields (Compute, Cloud Functions, Cloud SQL, IAM, etc.)
  - Request/response metadata

## Requirements

- Rust >= 1.70
- GCP project with audit logging enabled
- Pub/Sub subscription configured

## Build

```shell
make
```

Or directly with Cargo:

```shell
cargo build --release
```

The plugin will be built as `libgcpaudit.so` (or `.dylib` on macOS).

## Configuration

The plugin accepts the following configuration in `init_config`:

- `project_id`: Your GCP project ID (required)
- `credentials_file`: Path to GCP credentials JSON file (optional, defaults to application default credentials)
- `num_goroutines`: Number of concurrent workers for message processing (default: 10)
- `max_outstanding_messages`: Maximum number of unprocessed messages (default: 1000)
- `useAsync`: Enable async extraction optimization (default: true)

### Example Falco Configuration

```yaml
plugins:
  - name: gcpaudit
    library_path: libgcpaudit.so
    init_config:
      project_id: "your-gcp-project-id"
      credentials_file: ""  # Optional, uses default credentials
    open_params: "your-subscription-id"

load_plugins: [gcpaudit]
```

## Supported Fields

| Field Name | Description |
|------------|-------------|
| `gcp.user` | GCP principal email who committed the action |
| `gcp.callerIP` | GCP principal caller IP |
| `gcp.userAgent` | GCP principal caller useragent |
| `gcp.authorizationInfo` | GCP authorization information affected resource |
| `gcp.serviceName` | GCP API service name |
| `gcp.policyDelta` | GCP service resource access policy |
| `gcp.request` | GCP API raw request |
| `gcp.methodName` | GCP API service method executed |
| `gcp.cloudfunctions.function` | GCF name |
| `gcp.cloudsql.databaseId` | GCP SQL database ID |
| `gcp.compute.instanceId` | GCE instance ID |
| `gcp.compute.networkId` | GCP network ID |
| `gcp.compute.subnetwork` | GCP subnetwork name |
| `gcp.compute.subnetworkId` | GCP subnetwork ID |
| `gcp.dns.zone` | GCP DNS zone |
| `gcp.iam.serviceAccount` | GCP service account |
| `gcp.iam.serviceAccountId` | GCP IAM unique ID |
| `gcp.location` | GCP region |
| `gcp.logging.sink` | GCP logging sink |
| `gcp.projectId` | GCP project ID |
| `gcp.resourceName` | GCP resource name |
| `gcp.resourceType` | GCP resource type |
| `gcp.resourceLabels` | GCP resource labels |
| `gcp.storage.bucket` | GCP bucket name |
| `gcp.time` | Timestamp of the event in RFC3339 format |

## Example Rules

```yaml
- rule: GCP Bucket configured to be public
  desc: Detect when access on a GCP Bucket granted to the public internet
  condition: >
    gcp.serviceName="storage.googleapis.com" and
    gcp.methodName="storage.setIamPermissions"
  output: >
    GCP bucket access granted to be public
    (user=%gcp.user
    ip=%gcp.callerIP
    project=%gcp.projectId
    bucket=%gcp.storage.bucket)
  priority: CRITICAL
  source: gcp_auditlog
```

## Development

### Running Tests

```shell
cargo test
```

### Linting

```shell
cargo clippy -- -D warnings
```

### Formatting

```shell
cargo fmt
```

## License

Apache-2.0

## Contact

github.com/falcosecurity/plugins
