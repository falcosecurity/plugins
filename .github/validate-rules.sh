#!/bin/bash

falco_image=$1
checker_tool=$2
config_file=$3
rules_files=$4

# craft rules validation command
validation_flags=""
for rules_file in $rules_files; do
    validation_flags="${validation_flags} -r ${rules_file}"
done

# append plugin files to validation command
configured_plugins="$(cat $config_file | grep 'library_path: ' | cut -d ':' -f 2 | xargs)"
for plugin_lib in $configured_plugins; do
    validation_flags="${validation_flags} -f /usr/share/falco/plugins/${plugin_lib}"
done

chmod +x $checker_tool
echo $checker_tool validate -c $config_file $validation_flags
$checker_tool validate --falco-image=$falco_image -c $config_file $validation_flags
