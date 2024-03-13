#!/bin/bash
set -o errexit
set -o nounset
set -o pipefail
# Plugins for which we need to check if there exist as alternative plugin.
# If so, then we set them as a dependency. This is a must for rulesfiles
# that have multiple plugins that satisfy their requirements and the plugin we are
# checking is an alternative.
# It accepts a single value or coma separated values.
PLUGINS=$1

filtered_entries=()

# Extract plugins requirement from all files and save in a local file.
# Combine the sections from multiple files and save the output to file.
yq eval-all --no-doc '.[].required_plugin_versions | select(. != null and . != "")' ${@:2} > combined_requirements.yaml
# Remove duplicates from the top level.
yq eval-all --inplace 'unique_by(.name)' combined_requirements.yaml

#echo $(cat combined_requirements.yaml)

for YAML_FILE in "combined_requirements.yaml"; do
  #echo "Processing file $YAML_FILE"
  # Get the length of the entries list
  length=$(yq eval '. | length' "$YAML_FILE")
  # Iterate over each index in the entries list
  for ((i = 0; i < length; i++)); do
      # Access the entry by index using yq
      entry=$(yq eval '.['"$i"']' "$YAML_FILE")

      # Extract name and version from the entry
      name=$(echo "$entry" | yq eval '.name' -)
      version=$(echo "$entry" | yq eval '.version' -)
      # If a plugin we are considering exists as an alternative of another one, then we just skip.
      # This case could happen when we are processing multiple files and one of them overrides the
      # plugin since it has some specific rules for that plugin.
      to_be_skipped=false
      for alternative in $(yq eval  '.[].alternatives[].name' combined_requirements.yaml);do
        if [[  "$alternative" == "$name" ]]; then
          to_be_skipped=true

          break
        fi
      done

      if [ "$to_be_skipped" = true ];then
        #echo "skipping plugin ${name} because already an alternative"
        continue
      fi

      # Check if alternatives exist
      alternatives=$(echo "$entry" | yq eval '.alternatives[]?')
      if [ -n "$alternatives" ]; then
          is_alternative=false
          # Get the length of the alternatives list
          alt_length=$(echo "$entry" | yq eval '.alternatives | length' -)
          # Iterate over each alternative
          for ((j = 0; j < alt_length; j++)); do
              alt_entry=$(echo "$entry" | yq eval '.alternatives['"$j"']?' -)
              alt_name=$(echo "$alt_entry" | yq eval '.name' -)
              alt_version=$(echo "$alt_entry" | yq eval '.version' -)
              # If our plugin is set as an alternative then we use it as a dependency.
              if [[ " ${PLUGINS//,/ } " =~ " $alt_name " ]]; then
                  #echo "Preferring alternative plugin ${alt_name} over ${name}"
                  is_alternative=true
                  name=$alt_name
                  version=$alt_version
                  break
              fi
          done
      fi
    filtered_entries+=("$name:$version")
  done
done

# Output the filtered entries
printf "%s\n" "${filtered_entries[@]}"
