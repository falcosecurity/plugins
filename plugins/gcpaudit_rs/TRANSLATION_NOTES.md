# Rust Translation Notes

## Translation from Go to Rust

This plugin has been translated from the original Go implementation to Rust. Below are the key differences and considerations:

### Architecture Changes

1. **Async Runtime**: The Rust version uses Tokio for async operations instead of Go's goroutines
2. **Channel Communication**: Uses `tokio::sync::mpsc` instead of Go channels
3. **JSON Parsing**: Uses `serde_json` instead of `fastjson`
4. **Error Handling**: Uses `anyhow::Result` for error propagation

### Key Components

#### 1. Configuration (`config.rs`)
- Maintains same configuration options as Go version
- Uses `serde` for JSON deserialization
- Implements `Default` trait for default values

#### 2. Source Plugin (`source.rs`)
- Implements GCP Pub/Sub integration using `google-cloud-pubsub` crate
- Handles retry logic with exponential backoff
- Runs message receiver in background tokio task

#### 3. Field Extraction (`extract.rs`)
- Caches parsed JSON to avoid re-parsing on same event
- Uses JSON pointer syntax for field access
- Supports all 25 fields from original Go implementation

### Crate Dependencies

The main dependencies are:

- `falco_plugin`: Rust SDK for Falco plugins
- `google-cloud-pubsub`: GCP Pub/Sub client
- `serde`/`serde_json`: JSON serialization
- `tokio`: Async runtime
- `anyhow`: Error handling

### Building

```bash
cargo build --release
```

The output will be a shared library (`libgcpaudit.so` or `.dylib`) that can be loaded by Falco.

### Testing Considerations

When testing this plugin:

1. Ensure GCP credentials are properly configured
2. Set up a test Pub/Sub subscription
3. Verify field extraction matches expected JSON structure
4. Test retry logic and error handling

### Known Limitations

1. The google-cloud-pubsub API may differ from the Go client - verify authentication methods
2. Message batching behavior may differ slightly from Go version
3. Performance characteristics will differ due to Rust vs Go runtime

### Future Improvements

- Add comprehensive unit tests
- Add integration tests with mock Pub/Sub
- Optimize JSON parsing with zero-copy deserialization
- Add metrics/observability hooks
- Support for additional authentication methods
