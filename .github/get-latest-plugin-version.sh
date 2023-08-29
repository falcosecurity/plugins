#!/bin/bash

PLUGIN=$1

set +e pipefail
echo Searching tag with prefix prefix \"${PLUGIN}-\"...
git fetch --tags origin
latest_tag=`git describe --match="${PLUGIN}-*.*.*" --exclude="${PLUGIN}-*.*.*-*" --abbrev=0 --tags $(git rev-list --tags="${PLUGIN}-*.*.*" --max-count=1)`
set -e pipefail

latest_ver="0.0.0"
if [ -z "$latest_tag" ]
then
  echo Not previous tag has been found
else
  echo Most recent tag found is \"$latest_tag\"
  latest_ver=$(echo $latest_tag | cut -d '-' -f 2-)
fi

echo Setting plugin version for "${PLUGIN}" to $latest_ver
echo "version=$latest_ver" >> $GITHUB_OUTPUT
echo "ref=${PLUGIN}-$latest_ver" >> $GITHUB_OUTPUT
