#!/bin/bash

RULES_FILE=$1
CONFIG_FILE=$2
PLUGIN_NAME=$3
RESULT_FILE=$4
CHECKER_TOOL=$5
FALCO_DOCKER_IMAGE=$6

set -e pipefail

rm -f $RESULT_FILE
touch $RESULT_FILE

cur_branch=`git rev-parse HEAD`
echo Current branch is \"$cur_branch\"
echo Checking version for rules file \"$RULES_FILE\"...
cp $RULES_FILE tmp_rule_file.yaml

echo Searching tag with prefix prefix \"$PLUGIN_NAME-\"...
latest_tag=`git describe --match="$PLUGIN_NAME-*.*.*" --exclude="$PLUGIN_NAME-*.*.*-*" --abbrev=0 --tags $(git rev-list --tags="$PLUGIN_NAME-*.*.*" --max-count=1)`

if [ -z "$latest_tag" ]
then
    echo Not previous tag has been found
    exit 0
else
    echo Most recent tag found is \"$latest_tag\"
fi

git checkout tags/$latest_tag
chmod +x $CHECKER_TOOL
$CHECKER_TOOL \
    compare \
    --falco-image=$FALCO_DOCKER_IMAGE \
    -c $CONFIG_FILE \
    -l $RULES_FILE \
    -r tmp_rule_file.yaml \
1>tmp_res.txt
git switch --detach $cur_branch

echo '##' $(basename $RULES_FILE) >> $RESULT_FILE
echo Comparing \`$cur_branch\` with latest tag \`$latest_tag\` >> $RESULT_FILE
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
