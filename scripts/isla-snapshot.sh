#!/usr/bin/env bash
# Fetches sail-arm's Armv9.4-A model as isla's Jib IR snapshot, the input of
# `tools/isla-check`, and checks its SHA-256.
#
# The snapshot comes from rems-project/isla-snapshots (`armv9p4.ir.gz`,
# built from sail-arm's `arm-v9.4-a` model). Like sail-arm, it is licensed
# under the BSD 3-Clause Clear licence; it is not checked in.
#
# Usage: scripts/isla-snapshot.sh [dir]
#   dir  where `armv9p4.ir` goes (default ~/.cache/binbun-isla)
# Needs: curl, sha256sum, gunzip.
set -euo pipefail

dest="${1:-$HOME/.cache/binbun-isla}"
commit=d8b31014643035a3b11071e56ef30001de3f52ab
sha256=d8c547eefd125a8bd01a827d2733fc9eddbc415839e8d278310e527c7721a3db
url="https://raw.githubusercontent.com/rems-project/isla-snapshots/$commit/armv9p4.ir.gz"

mkdir -p "$dest"
if [[ -f "$dest/armv9p4.ir.gz" ]] && echo "$sha256  $dest/armv9p4.ir.gz" | sha256sum --check --status; then
    echo "have $dest/armv9p4.ir.gz"
else
    curl --fail --location --silent --show-error --output "$dest/armv9p4.ir.gz.part" "$url"
    echo "$sha256  $dest/armv9p4.ir.gz.part" | sha256sum --check --status || {
        echo "armv9p4.ir.gz: checksum mismatch" >&2
        exit 1
    }
    mv "$dest/armv9p4.ir.gz.part" "$dest/armv9p4.ir.gz"
fi
gunzip --keep --force "$dest/armv9p4.ir.gz"
echo "$dest/armv9p4.ir"
