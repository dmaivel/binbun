#!/usr/bin/env bash
# The root workspace's crates.io crates at VERSION: every package not
# marked `publish = false` (the `binbun` command's crates, the decoders'
# one API `binbun-disasm` and the C library's), each
# checked to be at VERSION.
#
#   scripts/release/publish-crates.sh package X.Y.Z
#       packages each and builds it from its package alone (`cargo
#       package`): what crates.io will get, nothing uploaded.
#   scripts/release/publish-crates.sh publish X.Y.Z
#       publishes them in dependency order (`cargo publish --workspace`,
#       which waits for each to reach the index before publishing what
#       depends on it), without building them again (run `package`
#       first). Safe to run again after a failure: a crate whose VERSION
#       is already on crates.io (its sparse index entry) is left out, so
#       a retry publishes only what is missing.
#
# CARGO_REGISTRY_TOKEN is the token for `publish` (the release
# workflow's comes from crates.io's trusted publishing and lasts 30
# minutes, hence the build beforehand). Needs cargo, curl and jq.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(dirname "$0")/common.sh"

usage="usage: $0 package|publish X.Y.Z"
command=${1:?$usage}
version=${2:?$usage}
index=${CRATES_IO_INDEX:-https://index.crates.io}

# The sparse index's path of crate $1 (its name in lower case).
index_path() {
    local name
    name=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
    case ${#name} in
        1) echo "1/$name" ;;
        2) echo "2/$name" ;;
        3) echo "3/${name:0:1}/$name" ;;
        *) echo "${name:0:2}/${name:2:2}/$name" ;;
    esac
}

# Whether crate $1 has version $2 on crates.io (exit 0) or not (exit 1);
# dies when the index cannot be read.
published() {
    local entry status
    entry=$(mktemp)
    status=$(curl -sS --retry 3 -o "$entry" -w '%{http_code}' "$index/$(index_path "$1")") ||
        die "cannot read the index entry of $1"
    case $status in
        200) jq -es --arg version "$2" 'any(.[]; .vers == $version)' "$entry" >/dev/null && { rm -f "$entry"; return 0; } ;;
        404) ;;
        *) rm -f "$entry"; die "the index answered $status for $1" ;;
    esac
    rm -f "$entry"
    return 1
}

cd "$root"
# Name and version of each package to publish (`publish` unset; a list
# would name the registries allowed, none of binbun's does).
packages=$(cargo metadata --format-version 1 --no-deps --locked |
    jq -r '.packages[] | select(.publish == null) | "\(.name) \(.version)"')
[ -n "$packages" ] || die "no package to publish"

selected=()
while read -r name crate_version; do
    [ "$crate_version" = "$version" ] || die "$name is at $crate_version, not $version"
    selected+=(--package "$name")
done <<EOF
$packages
EOF

case $command in
    package)
        cargo package --locked "${selected[@]}"
        exit 0
        ;;
    publish) ;;
    *) die "$usage" ;;
esac

excluded=()
missing=0
while read -r name _; do
    if published "$name" "$version"; then
        echo "$name $version: already on crates.io"
        excluded+=(--exclude "$name")
    else
        echo "$name $version: to publish"
        missing=$((missing + 1))
    fi
done <<EOF
$packages
EOF

if [ "$missing" -eq 0 ]; then
    echo "every crate is on crates.io at $version"
    exit 0
fi
cargo publish --locked --no-verify --workspace ${excluded[@]+"${excluded[@]}"}
