#!/bin/sh
# Lists the commits since the last release tag (vX.Y.Z), oldest first, as
# raw material for CHANGELOG.md's "## Unreleased" section: check that
# every change a user would notice has its line there, written as what
# users can do, not as these subjects. Nothing is written.
#
#   scripts/release/changelog-draft.sh [SINCE]
#
# SINCE: a tag or commit to start after (default the newest v* tag
# reachable from HEAD; every commit if there is none).
set -eu

cd "$(dirname "$0")/../.."
since=${1:-$(git describe --tags --abbrev=0 --match 'v[0-9]*' 2>/dev/null || true)}
if [ -n "$since" ]; then
    range=$since..HEAD
    echo "# Commits since $since"
else
    range=HEAD
    echo "# Commits (no release tag yet)"
fi
echo "# Already under \"## Unreleased\": compare before adding lines."
echo
git log --reverse --no-merges --format='- %s (%h, %as)' "$range"
