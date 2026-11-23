#!/bin/sh
# Builds Intel XED at the commits third_party/xed/VERSION records (XED and
# mbuild side by side in DIR), for the XED oracle (scripts/xed-oracle.sh
# DIR/xed) and the differential fuzzer (XED_DIR=DIR/xed).
#
#   scripts/ci/build-xed.sh DIR
#
# Needs: git, python3, a C compiler.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
dir=${1:?usage: $0 DIR}
xed_commit=$(sed -n 's/^commit //p' "$root/third_party/xed/VERSION")
mbuild_commit=$(sed -n 's/^mbuild //p' "$root/third_party/xed/VERSION")

fetch() { # repository commit directory
    git init --quiet "$3"
    git -C "$3" fetch --quiet --depth 1 "https://github.com/intelxed/$1.git" "$2"
    git -C "$3" checkout --quiet FETCH_HEAD
}

mkdir -p "$dir"
fetch xed "$xed_commit" "$dir/xed"
fetch mbuild "$mbuild_commit" "$dir/mbuild"
# Optimised: XED's default build is not.
(cd "$dir/xed" && python3 mfile.py --opt=3 -j "$(nproc)")
echo "$dir/xed (XED $xed_commit)"
