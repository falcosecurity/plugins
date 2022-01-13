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

import yaml
import sys

def check_conflicts(root: dict):
    if 'plugins' not in root:
        print('plugins entry not found')
        return False

    if 'source' not in root['plugins']:
        print('plugins.source entry not found')
        return False

    ids = []
    sources = []
    for plugin in root['plugins']['source']:
        id = plugin['id']
        source = plugin['source']
        if id in ids:
            print('check_conflicts: ID \'{0}\' is not unique'.format(id))
            return False
        if source in sources:
            print('check_conflicts: Event Source \'{0}\' is not unique'.format(source))
            return False
        ids.append(plugin['id'])
        sources.append(plugin['source'])
    return True


def main():
    if len(sys.argv) < 2:
        print("Usage: check.py <registry_file>")
        exit(1)
    registry_filename = sys.argv[-1]

    print("Open registry file '{0}'".format(registry_filename))
    with open(registry_filename, "r") as yamlfile:
        try:
            print("Load registry from YAML")
            root = yaml.safe_load(yamlfile)
            print("Check for ID and Event Source conflicts")
            if not check_conflicts(root):
                exit(1)
        except yaml.YAMLError as e:
            print(e)
            exit(1)


if __name__ == "__main__":
    main()