#!/bin/bash

RULES_DIR=$1
CONFIG_FILE=$2
PLUGIN_NAME=$3
RESULT_FILE=$4
CHECKER_TOOL=$5
FALCO_DOCKER_IMAGE=$6
LATEST_TAG=$7

set -e pipefail

rm -f $RESULT_FILE
touch $RESULT_FILE

extra_flags=""
loaded_plugins="$(cat $CONFIG_FILE | grep 'library_path: ' | cut -d ':' -f 2 | xargs)"
for plugin_lib in $loaded_plugins; do
    extra_flags="${extra_flags} -f /usr/share/falco/plugins/${plugin_lib}"
done

cur_branch=`git rev-parse HEAD`
echo Current branch is \"$cur_branch\"
echo Checking version for rules file in dir \"$RULES_DIR\"...
# Get the rules files and save them.
# We sort the rules files but first we remove the file extension.
rules_files=$(ls ${RULES_DIR}/* | while read -r line; do echo "${line%.yaml}"; done | sort)
# Add the extension to the files.
# Append the .yaml extension back to the sorted strings
rules_files=$(echo "${rules_files}" | sed 's/$/.yaml/')
echo Rule files found: ${rules_files}

# We save the current rules files before going back to the previous
# version.
prefix="tmp-"
for rules_file in ${rules_files}; do
    new_file="${prefix}$(basename "$rules_file")"
    echo "Copying rules file ${rules_file} to temporary file ${new_file}"
    cp "$rules_file" "$new_file"
    tmp_rules+=" $new_file"
done

git checkout tags/$LATEST_TAG
chmod +x $CHECKER_TOOL
$CHECKER_TOOL \
    compare \
    --falco-image=$FALCO_DOCKER_IMAGE \
    -c $CONFIG_FILE \
    -l ${rules_files} \
    -r ${tmp_rules} \
    ${extra_flags} \
1>tmp_res.txt
git switch --detach $cur_branch

echo '##' $(basename $RULES_DIR) >> $RESULT_FILE
echo Comparing \`$cur_branch\` with latest tag \`$LATEST_TAG\` >> $RESULT_FILE
echo "" >> $RESULT_FILE
if [ -s tmp_res.txt ]
then
    cat tmp_res.txt >> $RESULT_FILE
else
    echo "No changes detected" >> $RESULT_FILE
fi
echo "" >> $RESULT_FILE

rm -f ${tmp_rules}
rm -f tmp_res.txt
