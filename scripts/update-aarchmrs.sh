#!/usr/bin/env bash
# Replaces third_party/aarchmrs with a release of Arm's BSD AARCHMRS package.
#
# The tarball is vendored unchanged; the generator reads it directly. Only
# docs/notice.html (the licence) is extracted next to it.
#
# Usage: scripts/update-aarchmrs.sh [release [sha256]]
#   release  e.g. 2026-09 (the default)
#   sha256   expected checksum; required for any release but the default
# Needs: curl, sha256sum, tar.
set -euo pipefail

release="${1:-2026-09}"
default_sha256=d5bf3f538663fb18be081ba8e9f08b188ed06f81dd19d4aa2da5b2795103a4ec
if [[ $# -ge 2 ]]; then
    sha256="$2"
elif [[ "$release" == 2026-09 ]]; then
    sha256="$default_sha256"
else
    echo "give the expected sha256 of release $release" >&2
    exit 1
fi

name="AARCHMRS_OPENSOURCE_A_profile_FAT-$release.tar.gz"
url="https://developer.arm.com/-/cdn-downloads/permalink/Exploration-Tools-OS-Machine-Readable-Data/AARCHMRS_BSD/$name"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="$root/third_party/aarchmrs"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl --fail --location --silent --show-error --output "$work/$name" "$url"
echo "$sha256  $work/$name" | sha256sum --check --quiet
tar -xzf "$work/$name" -C "$work" docs/notice.html

rm -f "$dest"/AARCHMRS_OPENSOURCE_A_profile_FAT-*.tar.gz
mkdir -p "$dest"
cp "$work/$name" "$dest/$name"
cp "$work/docs/notice.html" "$dest/notice.html"

echo "updated $dest: $name ($(stat -c %s "$dest/$name") bytes, sha256 $sha256)"
echo "update the release, size and checksums in $dest/README.md and the PACKAGE path in xtask/src/aarch64"
