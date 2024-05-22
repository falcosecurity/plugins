#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2023 The Falco Authors.
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

plugin=$1

if [ -z "$plugin" ]; then
    echo "Usage changelog-gen.sh <plugin_name>"
    exit 1
fi

tool=./build/changelog/bin/changelog

to=""
from=""
tags="$(git tag -l | grep -E -e ${plugin}-[0-9]+.[0-9]+.[0-9]+ -e ${plugin}/v[0-9]+.[0-9]+.[0-9]+ | grep -E -v ${plugin}-[0-9]+.[0-9]+.[0-9]+-rc | sort -V -r)"

# print title
echo "# Changelog"
echo ""

# generate entry for upcoming tag
head="$(git rev-parse HEAD)"
echo "## dev"
echo ""
${tool} --from="" --to=${head} --plugin=${plugin}
echo ""

# generate entry for each tag
for tag in $tags
do
    from=$tag
    if [ ! -z "$to" ]; then
        ver=""
        # support both the old and new tag formats
        if [[ $to == plugins/* ]]; then
            ver="$(echo ${to} | sed -e s/^plugins\\/${plugin}\\///)"
        else
            ver="$(echo ${to} | sed -e s/^${plugin}-// -e s/^/v/)"
        fi
        echo "## ${ver}" 
        echo ""
        ${tool} --from=${from} --to=${to} --plugin=${plugin}
        echo "" 
    fi
    to=$tag
done

# generate last entry for first tag, starting from the first commit
if [ -n "$to" ]; then
    from="$(git rev-list --max-parents=0 HEAD)"
    ver="$(echo ${to} | sed -e s/^${plugin}-// -e s/^/v/)"
    echo "## ${ver}" 
    echo ""
    ${tool} --from=${from} --to=${to} --plugin=${plugin}
    echo "" 
fi
