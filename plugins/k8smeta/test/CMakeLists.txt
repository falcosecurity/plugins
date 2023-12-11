include(libs)

# ##############################################################################
# Build test server
# ##############################################################################

# Set some test paths inside the collector
set(TEST_SERVER_FOLDER "${K8S_METACOLLECTOR_DIR}/test/server")
set(TEST_JSON_FILE "${TEST_SERVER_FOLDER}/test.json")

add_custom_target(build-server COMMAND cd "${TEST_SERVER_FOLDER}" && go build .)
add_custom_target(run-server COMMAND "${TEST_SERVER_FOLDER}/test_server" --file
                                     "${TEST_JSON_FILE}")

# ##############################################################################
# Build tests
# ##############################################################################

# Create a build directory out of the tree for libs tests
set(SINSP_TEST_FOLDER "${CMAKE_BINARY_DIR}/libs_tests")
file(MAKE_DIRECTORY "${SINSP_TEST_FOLDER}")

# Prepare some additional includes for plugin tests
set(TEST_EXTRA_INCLUDES "${CMAKE_BINARY_DIR}/plugin_include/k8smeta_tests")
# Put a file with test macros into the build dir
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/plugin_test_var.h.in"
               "${TEST_EXTRA_INCLUDES}/plugin_test_var.h")
# Copy an include shared with the plugin into the build dir
configure_file("${CMAKE_SOURCE_DIR}/src/shared_with_tests_consts.h"
               "${TEST_EXTRA_INCLUDES}/shared_with_tests_consts.h" COPYONLY)
# Download nlohmann json single include used in tests
file(
  DOWNLOAD
  "https://raw.githubusercontent.com/nlohmann/json/v3.10.2/single_include/nlohmann/json.hpp"
  "${TEST_EXTRA_INCLUDES}/json.hpp"
  EXPECTED_HASH
    SHA256=059743e48b37e41579ee3a92e82e984bfa0d2a9a2b20b175d04db8089f46f047)

# Add some additional test source files
file(GLOB_RECURSE K8S_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
string(REPLACE ";" "\\;" ESCAPED_K8S_TEST_SUITE "${K8S_TEST_SUITE}")

# Associate the needed includes
list(APPEND K8S_TEST_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/include"
     "${CMAKE_BINARY_DIR}/plugin_include")
string(REPLACE ";" "\\;" ESCAPED_K8S_TEST_INCLUDES "${K8S_TEST_INCLUDES}")

add_custom_target(
  build-tests
  WORKING_DIRECTORY "${SINSP_TEST_FOLDER}"
  COMMAND
    cmake -S"${LIBS_DIR}" -DCMAKE_BUILD_TYPE=Release -DUSE_BUNDLED_DEPS=ON
    -DBUILD_LIBSCAP_GVISOR=OFF -DCREATE_TEST_TARGETS=ON -DMINIMAL_BUILD=ON
    -DSCAP_FILES_SUITE_ENABLE=OFF
    -DADDITIONAL_SINSP_TESTS_SUITE="${ESCAPED_K8S_TEST_SUITE}"
    -DADDITIONAL_SINSP_TESTS_INCLUDE_FOLDERS="${ESCAPED_K8S_TEST_INCLUDES}"
  COMMAND make -C "${SINSP_TEST_FOLDER}" unit-test-libsinsp -j4)

add_custom_target(
  run-tests COMMAND "${SINSP_TEST_FOLDER}/libsinsp/test/unit-test-libsinsp"
                    --gtest_filter='*plugin_k8s*')
