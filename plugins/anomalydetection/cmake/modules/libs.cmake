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

message(STATUS "Fetching libs at 'https://github.com/falcosecurity/libs.git'")

FetchContent_Declare(
  libs
  GIT_REPOSITORY https://github.com/falcosecurity/libs.git
  GIT_TAG c6ff3d0731c6873c4fa9bf8df57480fe833aa710
  CONFIGURE_COMMAND "" BUILD_COMMAND "")

FetchContent_MakeAvailable(libs)
set(LIBS_INCLUDE "${libs_SOURCE_DIR}")
set(LIBS_DIR "${libs_SOURCE_DIR}")
message(STATUS "Using libs include at '${LIBS_INCLUDE}'")
