#!/bin/bash

PLUGIN=$1

set +e pipefail
echo Searching tag with prefix prefix \"${PLUGIN}-\"...
git fetch --tags origin
latest_tag=`git describe --match="${PLUGIN}-[0-9]*" --match="plugins/${PLUGIN}/v*" --abbrev=0 --tags`
set -e pipefail

latest_ver="0.0.0"
if [ -z "$latest_tag" ]
then
  echo Not previous tag has been found
else
  echo Most recent tag found is \"$latest_tag\"
  if [[ "${latest_tag}" == "plugins/${PLUGIN}"* ]]; then
      latest_ver="${latest_tag##*/v}"
  else
      latest_ver="${latest_tag##*-}"
  fi
fi

echo Setting plugin version for "${PLUGIN}" to $latest_ver
echo "version=$latest_ver" >> $GITHUB_OUTPUT
echo "ref=${latest_tag}" >> $GITHUB_OUTPUT
