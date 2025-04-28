# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2025 The Falco Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

#!/bin/bash

# This is a git pre-commit-msg hook which automatically add a DCO signed-off message if one is missing.

MESSAGE_FILE="$1"
GIT_AUTHOR=$(git var GIT_AUTHOR_IDENT)
SIGNOFF_BY=$(echo "$GIT_AUTHOR" | sed -n 's/^\(.*>\).*$/Signed-off-by: \1/p')

# Verify if a DCO signoff message exists.
# Append a DCO signoff message if one doesn't exist.
if ! grep -qs "^$SIGNOFF_BY" "$MESSAGE_FILE" ; then
  echo -e "\n$SIGNOFF_BY" >> "$MESSAGE_FILE"
fi
exit 0
