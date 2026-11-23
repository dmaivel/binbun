#!/bin/sh
# Builds tools/xed-oracle against a built XED kit.
#
#   scripts/xed-oracle.sh /path/to/xed [output]
#
# The XED checkout must have been built (`python3 mfile.py` in it), which
# leaves the kit in obj/wkit. The default output is target/xed-oracle.
set -eu

xed=${1:?usage: $0 /path/to/xed [output]}
root=$(cd "$(dirname "$0")/.." && pwd)
out=${2:-$root/target/xed-oracle}
kit=$xed/obj/wkit

mkdir -p "$(dirname "$out")"
cc -O2 -std=c99 -I"$kit/include" "$root/tools/xed-oracle/oracle.c" "$kit/lib/libxed.a" -o "$out"
echo "$out"
