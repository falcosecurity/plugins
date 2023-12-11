# Tests with libsinsp

To run the k8s plugin tests we use the libsinsp framework tests, in this way we can check the compatibility with the plugin and a specific framework version

## Run tests

```bash
make build-server
make run-server
make build-tests
make run-tests
```
