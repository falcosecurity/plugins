# Tests Leveraging `libsinsp` Unit Tests Framework

We leverage the [falcosecurity/libs](https://github.com/falcosecurity/libs) `libsinsp` unit test framework for the `anomalydetection` plugin tests. This way, we can check the compatibility of the plugin with a specific framework version. This approach was adopted from the `k8smeta` plugin.

## Run Tests

```bash
cd build
# Build tests
make build-tests
# Run tests
make run-tests
```