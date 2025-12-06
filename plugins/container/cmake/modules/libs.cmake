# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2025 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
# in compliance with the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License
# is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
# or implied. See the License for the specific language governing permissions and limitations under
# the License.

include(FetchContent)

# Allow override via command line: cmake -DLIBS_REPO=... -DLIBS_VERSION=...
if(NOT DEFINED LIBS_REPO)
    set(LIBS_REPO "https://github.com/falcosecurity/libs.git")
endif()

if(NOT DEFINED LIBS_VERSION)
    # Using a specific commit because there is no tagged version yet including
    # the target used for the test.
    set(LIBS_VERSION "35f5e2366cc6075bdc0a51faf2077e7a9c1e03a7")
endif()

if(DEFINED LIBS_DIR)
    message(STATUS "Using libs from local directory '${LIBS_DIR}'")
    FetchContent_Declare(
        libs
        SOURCE_DIR ${LIBS_DIR}
    )
else()
    message(STATUS "Fetching libs from '${LIBS_REPO}' at version '${LIBS_VERSION}'")
    FetchContent_Declare(
        libs
        GIT_REPOSITORY ${LIBS_REPO}
        GIT_TAG ${LIBS_VERSION}
    )
endif()

# Set libs build options before FetchContent_MakeAvailable
set(USE_BUNDLED_DEPS ON CACHE BOOL "Enable bundled dependencies" FORCE)
set(CREATE_TEST_TARGETS ON CACHE BOOL "Enable test targets (sinsp_test_support)" FORCE)
set(BUILD_LIBSCAP_GVISOR OFF CACHE BOOL "Disable gVisor support" FORCE)
set(MINIMAL_BUILD ON CACHE BOOL "Enable minimal build" FORCE)

FetchContent_MakeAvailable(libs)