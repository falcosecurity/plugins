#!/bin/bash

PLUGIN=$1

# set expected paths for plugins' config and rules files
rules_dir="$GITHUB_WORKSPACE/plugins/${PLUGIN}/rules"
config_file="$GITHUB_WORKSPACE/plugins/${PLUGIN}/falco.yaml"

# set paths into step outputs
echo "rules_dir=${rules_dir}" >> "$GITHUB_OUTPUT"
echo "config_file=${config_file}" >> "$GITHUB_OUTPUT"

# craft a default falco.yaml if no custom one is available
if [ ! -f "$config_file" ]; then
  # we assume that the current plugin is always a dependency
  deps="$PLUGIN"

  # we collect all plugin dependencies across all plugin rulesets
  # todo(jasondellaluce): find a way to avoid ignoring alternatives
  if [ -d "$rules_dir" ]; then
    rules_files=$(ls $rules_dir/*)
    echo Extracting plugin dependencies from rules file "${rules_files}"...
    rules_deps=$($GITHUB_WORKSPACE/.github/extract-plugins-deps-from-rulesfile.sh $PLUGIN $rules_files)
    echo "${rules_deps}"
  fi

  mkdir -p $(echo $config_file | sed 's:[^/]*$::')
  touch $config_file
  echo "plugins:" >> $config_file
  for dep in $rules_deps; do
    dep=$(echo $dep | tr -d '"' | cut -d ':' -f 1)
    echo "  - name: ${dep}" >> $config_file
    echo "    library_path: lib${dep}.so" >> $config_file
  done
fi

echo Using config file "${config_file}"
cat ${config_file}
echo ""
