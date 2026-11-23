#!/usr/bin/env bash
# Checks that the Linux CLI's release archive is reproducible: builds it
# twice, from two copies of this tree at different paths into different
# target directories, and compares the archives byte for byte. The
# nightly workflow runs it in the release's container
# (scripts/release/linux-container.sh scripts/release/reproduce-check.sh).
#
#   scripts/release/reproduce-check.sh [WORK]
#
# WORK (default target/reproduce) holds both copies and their builds. On
# a difference, compare the two binaries with diffoscope.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(dirname "$0")/common.sh"

work=$(absolute_dir "${1:-$root/target/reproduce}")
# One time for both builds (the commit's, or the fixed fallback).
reproducible_env
unset RUSTFLAGS CFLAGS

for copy in first second-copy; do
    rm -rf "${work:?}/$copy"
    mkdir -p "$work/$copy/tree"
    (cd "$root" && tar --exclude=./target --exclude=./gui/target --exclude=./.git -cf - .) |
        tar -xf - -C "$work/$copy/tree"
    CARGO_TARGET_DIR=$work/$copy/target "$work/$copy/tree/scripts/release/package-linux.sh" \
        --cli-only --out "$work/$copy/dist" >/dev/null
done

status=0
for archive in "$work/first/dist"/*.tar.gz; do
    name=$(basename "$archive")
    one=$(sha256sum <"$archive" | cut -d ' ' -f 1)
    two=$(sha256sum <"$work/second-copy/dist/$name" | cut -d ' ' -f 1)
    if [ "$one" = "$two" ]; then
        echo "$name: reproducible ($one)"
    else
        echo "$name: differs ($one, $two)" >&2
        status=1
    fi
done
exit "$status"
