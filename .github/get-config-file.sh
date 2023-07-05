#!/bin/bash

PLUGIN=$1
CONFIG_FILE=$2
RULES_DIR=$3

# craft a default falco.yaml if no custom one is available
config_file=$CONFIG_FILE
if [ ! -f "$config_file" ]; then
  # we assume that the current plugin is always a dependency
  deps="$PLUGIN"

  # we collect all plugin dependencies across all plugin rulesets
  # todo(jasondellaluce): find a way to avoid ignoring alternatives
  rules_dir=$RULES_DIR
  if [ -d "$rules_dir" ]; then
    echo Extracting plugin dependencies from rules files...
    rules_files=$(ls $rules_dir/*)
    for rules_file in "$rules_files"; do
      echo Extracting plugin dependencies from rules file "${rules_file}"...
      rules_deps=$(cat $rules_file | yq -r '.[].required_plugin_versions | select(. != null and . != "")[] | [.name + ":" + .version] | @csv')
      for dep in $rules_deps; do
        plugin_name=$(echo $dep | tr -d '"' | cut -d ':' -f 1)
        if [[ ${deps} != *"$plugin_name"* ]]; then
          deps="${deps} "${plugin_name}
        fi
      done
    done
  fi

  mkdir -p $(echo $config_file | sed 's:[^/]*$::')
  touch $config_file
  echo "plugins:" >> $config_file
  for dep in $deps; do
    echo "  - name: ${dep}" >> $config_file
    echo "    library_path: lib${dep}.so" >> $config_file
  done
fi

echo Using config file "${config_file}"
cat ${config_file}
echo ""
