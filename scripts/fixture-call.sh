#!/bin/sh
# Builds tools/fixture-call, which calls a function of a static x86-64 ELF
# fixture natively on this processor (the profile test of the CLI,
# crates/binbun-cli/tests/profiles.rs).
#
#   scripts/fixture-call.sh [output]
#
# Linux x86-64 only. The default output is target/fixture-call.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/target/fixture-call}

mkdir -p "$(dirname "$out")"
cc -O2 -std=c11 -Wall -Wextra "$root/tools/fixture-call/fixture_call.c" -o "$out"
echo "$out"
