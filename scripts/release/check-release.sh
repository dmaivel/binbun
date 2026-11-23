#!/usr/bin/env bash
# Checks that the tree is ready to be released as tag vX.Y.Z, and prints
# X.Y.Z: the tag's version is both workspaces' version, the version the
# crates.io crates require of each other (Cargo.toml's pins) and the C
# library's version constants (core.h, binbun-capi's lib.rs),
# and CHANGELOG.md has a dated, non-empty section for it. The release
# workflow runs it first and stops the release on any failure.
#
#   scripts/release/check-release.sh vX.Y.Z
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(dirname "$0")/common.sh"

tag=${1:?usage: $0 vX.Y.Z}
[[ $tag =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.-]+)?$ ]] ||
    die "$tag is not a release tag (vX.Y.Z or vX.Y.Z-pre.N)"
version=${tag#v}
major=${BASH_REMATCH[1]} minor=${BASH_REMATCH[2]} patch=${BASH_REMATCH[3]}

failed=
fail() {
    echo "check-release.sh: $*" >&2
    failed=1
}

workspace=$(release_version)
[ "$workspace" = "$version" ] || fail "the workspaces' version is $workspace, the tag's $version"

# The crates.io crates require each other at exactly the release's
# version: each pin in [workspace.dependencies] (`version = "=X.Y.Z"`)
# on a crate of this workspace (one with a `path`; a third-party crate
# pinned exactly, as rmcp is, keeps its own version).
pins=$(awk '
    /^\[workspace\.dependencies\]/ { section = 1; next }
    /^\[/ { section = 0 }
    section && /path = / && /version = "=/ { name = $1; sub(/.*version = "=/, ""); sub(/".*/, ""); print name, $0 }
' "$root/Cargo.toml")
[ -n "$pins" ] || fail "Cargo.toml pins no crate's version"
while read -r name pin; do
    [ -z "$name" ] || [ "$pin" = "$version" ] || fail "Cargo.toml requires $name at =$pin, the tag is $version"
done <<EOF
$pins
EOF

header=$root/crates/binbun-capi/include/binbun/core.h
capi=$root/crates/binbun-capi/src/lib.rs
for part in MAJOR:$major MINOR:$minor PATCH:$patch; do
    name=${part%%:*} want=${part#*:}
    grep -Eq "^#define BINBUN_VERSION_$name $want\$" "$header" ||
        fail "core.h's BINBUN_VERSION_$name is not $want"
    grep -Eq "^pub const VERSION_$name: u32 = $want;\$" "$capi" ||
        fail "binbun-capi's VERSION_$name is not $want"
done

if "$root/scripts/release/changelog.sh" date "$version" >/dev/null; then
    "$root/scripts/release/changelog.sh" notes "$version" >/dev/null || failed=1
else
    failed=1
fi

[ -z "$failed" ] || exit 1
echo "$version"
