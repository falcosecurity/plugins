#!/usr/bin/env bash

###############################################################################
#                          clang-format-check.sh                              #
###############################################################################
# USAGE: ./clang-format-check.sh <version> <path> [<fallback-style>] [<exclude-regex>] [<include-regex>]
#
# Checks all C/C++/Protobuf/CUDA files for conforming to clang-format.
# Uses the system-installed clang-format-<version> binary (from apt).
#
# Produces a GitHub Actions job summary on failure with a list of
# non-conforming files and a deeplink to the commit.

set -uo pipefail

CLANG_FORMAT_MAJOR_VERSION="$1"
CHECK_PATH="${2:-.}"
FALLBACK_STYLE="${3:-llvm}"
EXCLUDE_REGEX="${4:-^$}"
INCLUDE_REGEX="${5:-^.*\.((((c|C)(c|pp|xx|\+\+)?$)|((h|H)h?(pp|xx|\+\+)?$))|(ino|pde|proto|cu))$}"

CLANG_FORMAT_BIN="clang-format-${CLANG_FORMAT_MAJOR_VERSION}"

if ! command -v "$CLANG_FORMAT_BIN" &>/dev/null; then
	echo "::error::${CLANG_FORMAT_BIN} not found. Install it first (e.g. apt-get install ${CLANG_FORMAT_BIN})." >&2
	exit 2
fi

cd "$GITHUB_WORKSPACE" || exit 2

if [[ ! -d $CHECK_PATH ]]; then
	echo "Not a directory in the workspace, fallback to all files." >&2
	CHECK_PATH="."
fi

# Print version for logs
"$CLANG_FORMAT_BIN" --version

# initialize exit code
exit_code=0

# Find source files
src_files=$(find "$CHECK_PATH" -name .git -prune -o -regextype posix-egrep -regex "$INCLUDE_REGEX" -print)

IFS=$'\n'
for file in $src_files; do
	# Skip files matching exclude regex
	if [[ ${file} =~ $EXCLUDE_REGEX ]]; then
		continue
	fi

	"$CLANG_FORMAT_BIN" \
		--dry-run \
		--Werror \
		--style=file \
		--fallback-style="$FALLBACK_STYLE" \
		"${file}" 2>&1

	if [[ $? -ne 0 ]]; then
		echo "* \`$file\`" >>failing-files.txt
		echo "Failed on file: $file" >&2
		exit_code=1
	fi
done

# Report failure in GitHub Actions job summary
if [[ $exit_code -ne 0 && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
	if [[ "${GITHUB_EVENT_NAME:-}" == "pull_request" ]]; then
		SHA="${PR_HEAD_SHA:-${GITHUB_SHA}}"
	else
		SHA="${GITHUB_SHA}"
	fi
	DEEPLINK="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/commit/${SHA}"
	echo -e "Format check failed on commit [${SHA:0:8}](${DEEPLINK}) with files:\n$(<failing-files.txt)" >>"$GITHUB_STEP_SUMMARY"
fi

exit "$exit_code"
