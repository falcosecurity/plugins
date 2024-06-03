# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2024 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

# Setup adopted from the `k8smeta` plugin

include(libs)

# Create a build directory out of the tree for libs tests
set(SINSP_TEST_FOLDER "${CMAKE_BINARY_DIR}/libs_tests")
file(MAKE_DIRECTORY "${SINSP_TEST_FOLDER}")

# Prepare some additional includes for plugin tests
set(TEST_EXTRA_INCLUDES "${CMAKE_BINARY_DIR}/plugin_include")
configure_file("${CMAKE_CURRENT_SOURCE_DIR}/plugin_test_var.h.in"
               "${TEST_EXTRA_INCLUDES}/plugin_test_var.h")
# Copy the entire plugin src directory for targeted additional unit tests
file(COPY "${CMAKE_SOURCE_DIR}/src/" DESTINATION "${TEST_EXTRA_INCLUDES}/")

# Download nlohmann json single include used in tests
file(
  DOWNLOAD
  "https://raw.githubusercontent.com/nlohmann/json/v3.10.2/single_include/nlohmann/json.hpp"
  "${TEST_EXTRA_INCLUDES}/json.hpp"
  EXPECTED_HASH
    SHA256=059743e48b37e41579ee3a92e82e984bfa0d2a9a2b20b175d04db8089f46f047)

# Download xxhash single include used in cms class unit tests
file(
  DOWNLOAD
  "https://raw.githubusercontent.com/Cyan4973/xxHash/v0.8.2/xxhash.h"
  "${TEST_EXTRA_INCLUDES}/xxhash.h"
  EXPECTED_HASH SHA256=be275e9db21a503c37f24683cdb4908f2370a3e35ab96e02c4ea73dc8e399c43)

# Add some additional test source files
file(GLOB_RECURSE ANOMALYDETECTION_TEST_SUITE ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
string(REPLACE ";" "\\;" ESCAPED_ANOMALYDETECTION_TEST_SUITE "${ANOMALYDETECTION_TEST_SUITE}")

# Associate the needed includes
list(APPEND ANOMALYDETECTION_TEST_INCLUDES "${CMAKE_CURRENT_SOURCE_DIR}/include"
     "${CMAKE_BINARY_DIR}/plugin_include")
string(REPLACE ";" "\\;" ESCAPED_ANOMALYDETECTION_TEST_INCLUDES "${ANOMALYDETECTION_TEST_INCLUDES}")

add_custom_target(
  build-tests
  WORKING_DIRECTORY "${SINSP_TEST_FOLDER}"
  COMMAND
    cmake -S"${LIBS_DIR}"
    -DCMAKE_BUILD_TYPE=Release
    -DUSE_BUNDLED_DEPS=ON
    -DBUILD_LIBSCAP_GVISOR=OFF
    -DCREATE_TEST_TARGETS=ON
    -DMINIMAL_BUILD=ON
    -DSCAP_FILES_SUITE_ENABLE=OFF
    -DADDITIONAL_SINSP_TESTS_SUITE="${ESCAPED_ANOMALYDETECTION_TEST_SUITE}"
    -DADDITIONAL_SINSP_TESTS_INCLUDE_FOLDERS="${ESCAPED_ANOMALYDETECTION_TEST_INCLUDES}"
  COMMAND make -C "${SINSP_TEST_FOLDER}" unit-test-libsinsp -j4)

add_custom_target(
  run-tests COMMAND "${SINSP_TEST_FOLDER}/libsinsp/test/unit-test-libsinsp"
                    --gtest_filter='*plugin_anomalydetection*')
