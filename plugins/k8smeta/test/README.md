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

To run only some tests you need to use the test binary directly

```bash
# from the `build` directory
./libs_tests/libsinsp/test/unit-test-libsinsp --gtest_filter='*plugin_k8s_PPME_SYSCALL_CLONE3_X_parse'
```
