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

message(
  STATUS
    "Fetching xxhash at 'https://raw.githubusercontent.com/Cyan4973/xxHash/v0.8.2/xxhash.h'"
)

FetchContent_Declare(
  # BSD 2-Clause License
  xxhash
  URL "https://raw.githubusercontent.com/Cyan4973/xxHash/v0.8.2/xxhash.h"
  URL_HASH SHA256=be275e9db21a503c37f24683cdb4908f2370a3e35ab96e02c4ea73dc8e399c43 
  DOWNLOAD_NAME "xxhash.h"
  DOWNLOAD_NO_EXTRACT TRUE
)

FetchContent_MakeAvailable(xxhash)
set(XXHASH_INCLUDE "${xxhash_SOURCE_DIR}")
message(STATUS "Using xxhash include at '${XXHASH_INCLUDE}'")
