#!/bin/bash

RULES_FILE=$1
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
echo Checking version for rules file \"$RULES_FILE\"...
cp $RULES_FILE tmp_rule_file.yaml

git checkout tags/$LATEST_TAG
chmod +x $CHECKER_TOOL
$CHECKER_TOOL \
    compare \
    --falco-image=$FALCO_DOCKER_IMAGE \
    -c $CONFIG_FILE \
    -l $RULES_FILE \
    -r tmp_rule_file.yaml \
    ${extra_flags} \
1>tmp_res.txt
git switch --detach $cur_branch

echo '##' $(basename $RULES_FILE) >> $RESULT_FILE
echo Comparing \`$cur_branch\` with latest tag \`$LATEST_TAG\` >> $RESULT_FILE
echo "" >> $RESULT_FILE
if [ -s tmp_res.txt ]
then
    cat tmp_res.txt >> $RESULT_FILE
else
    echo "No changes detected" >> $RESULT_FILE
fi
echo "" >> $RESULT_FILE

rm -f tmp_rule_file.yaml
rm -f tmp_res.txt
