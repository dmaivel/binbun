#!/usr/bin/env bash
# Regenerates third_party/xed from a pinned Intel XED commit.
#
# binbun reads XED's *aggregated* datafiles (obj/dgen/all-*.txt): XED's own
# build decides which extension files are included and in which order, and we
# vendor the result instead of re-implementing that logic.
#
# Usage: scripts/update-xed.sh [xed-commit] [mbuild-commit]
# Needs: git, python3.
set -euo pipefail

xed_commit="${1:-0bcb623}"
mbuild_commit="${2:-main}"

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dest="$root/third_party/xed"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

git -C "$work" clone --quiet https://github.com/intelxed/xed.git
git -C "$work/xed" checkout --quiet "$xed_commit"
git -C "$work" clone --quiet https://github.com/intelxed/mbuild.git
git -C "$work/mbuild" checkout --quiet "$mbuild_commit"

(cd "$work/xed" && python3 mfile.py -j "$(nproc)" >"$work/build.log" 2>&1) || {
    tail -n 40 "$work/build.log" >&2
    exit 1
}

# Decoder inputs only; the encoder files are added when binbun grows an encoder.
files=(
    all-dec-instructions.txt
    all-dec-patterns.txt
    all-dec-spine.txt
    all-fields.txt
    all-state.txt
    all-registers.txt
    all-widths.txt
    all-extra-widths.txt
    all-element-types.txt
    all-element-type-base.txt
    all-pointer-names.txt
    all-map-descriptions.txt
    all-chip-models.txt
    all-cpuid.txt
    all-conversion-table.txt
)

rm -rf "$dest"
mkdir -p "$dest"
for file in "${files[@]}"; do
    # `###FILE:` markers record absolute build paths; make them reproducible.
    sed "s|^###FILE: $work/|###FILE: |" "$work/xed/obj/dgen/$file" >"$dest/$file"
done
cp "$work/xed/LICENSE" "$dest/LICENSE"

{
    echo "commit $(git -C "$work/xed" rev-parse HEAD)"
    echo "version $(cat "$work/xed/VERSION")"
    echo "mbuild $(git -C "$work/mbuild" rev-parse HEAD)"
} >"$dest/VERSION"

echo "updated $dest:"
cat "$dest/VERSION"
