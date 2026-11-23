#!/bin/sh
# Puts the files binbun.org serves from the GitHub releases into Zola's
# static directory, before the build: each published release's install.sh
# as /install/X.Y.Z.sh, and the latest full release's install.sh and
# latest.json (the update feed) as /install.sh and /latest.json. The
# download page and the landing page's button offer the release
# latest.json names (site/zola.toml's [extra] version until there is
# one). The release workflow makes them (scripts/release/release-files.sh);
# before the first release there are none and the site goes without them.
# They are not committed (.gitignore).
#
#   scripts/site/release-files.sh site/static
#
# Needs gh, authenticated (GH_TOKEN), and GITHUB_REPOSITORY (owner/name)
# unless it is dmaivel/binbun.
set -eu

out=${1:?usage: $0 STATIC_DIR}
repository=${GITHUB_REPOSITORY:-dmaivel/binbun}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

releases=$(gh release list --repo "$repository" --exclude-drafts --limit 1000 --json tagName,isLatest \
    --jq '.[] | "\(.tagName) \(.isLatest)"')
tags=$(echo "$releases" | awk 'NF { print $1 }')
# The release marked Latest on GitHub (the release workflow marks each
# full release so, never a pre-release).
latest=$(echo "$releases" | awk '$2 == "true" { print $1 }')

if [ -z "$tags" ]; then
    echo "release-files.sh: no release yet: /install.sh, /install/ and /latest.json left out"
    exit 0
fi

mkdir -p "$out/install"
for tag in $tags; do
    gh release download "$tag" --repo "$repository" --pattern install.sh --dir "$work/$tag"
    cp "$work/$tag/install.sh" "$out/install/${tag#v}.sh"
done

if [ -n "$latest" ]; then
    gh release download "$latest" --repo "$repository" --pattern latest.json --dir "$work/$latest"
    cp "$work/$latest/install.sh" "$out/install.sh"
    cp "$work/$latest/latest.json" "$out/latest.json"
    echo "release-files.sh: /install.sh and /latest.json from $latest"
else
    echo "release-files.sh: pre-releases only: /install.sh and /latest.json left out"
fi
