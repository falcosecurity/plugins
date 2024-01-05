# Tests with libsinsp

To run the k8s plugin tests we use the libsinsp framework tests, in this way we can check the compatibility with the plugin and a specific framework version

## Run tests

```bash
cd build
# build the test server which emulates the remote collector
make build-server
# run the test server
make run-server
# build tests
make build-tests
# run tests against the test server
make run-tests
```
