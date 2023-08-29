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
