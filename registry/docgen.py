#!/usr/bin/env python

#
# Copyright (C) 2022 The Falco Authors.
#
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
#

import sys
import yaml

def write_source_plugins_table(root: dict):
    if 'plugins' not in root:
        return False

    if 'source' not in root['plugins']:
        return False

    print("## Source plugins\n")
    print("| ID | Event Source | Name | Description | Info |")
    print("| --- | --- | --- | --- | ---|")
    for plugin in root['plugins']['source']:
        print("| {0} | {1} | `{2}` | {3} | Authors: {4} <br/> Repository: {5} <br/> Contact: {6}|".format(
            plugin['id'],
            plugin['name'],
            plugin['source'],
            plugin['description'],
            plugin['authors'],
            plugin['repository'],
            plugin['contact'],
        ))
    return True


def write_extractor_plugins_table(root: dict):
    if 'plugins' not in root:
        return False

    if 'extractor' not in root['plugins']:
        return False

    print("## Extractor plugins\n")
    print("| Name | Extract Event Sources | Description | Info |")
    print("| --- | --- | --- | --- |")
    for plugin in root['plugins']['extractor']:
        print("| {0} | {1} | {2} | Authors: {3} <br/> Repository: {4} <br/> Contact: {5}|".format(
            plugin['name'],
            plugin['source'],
            plugin['description'],
            plugin['authors'],
            plugin['repository'],
            plugin['contact'],
        ))
    return True


def main():

    if len(sys.argv) < 2:
        print("Usage: check.py <registry_file>")
        exit(1)
    registry_filename = sys.argv[-1]

    with open(registry_filename, "r") as yamlfile:
        try:
            root = yaml.safe_load(yamlfile)
            if not write_source_plugins_table(root) or not write_extractor_plugins_table(root):
                exit(1)
        except yaml.YAMLError as e:
            print(e)
            exit(1)

if __name__ == "__main__":
    main()
