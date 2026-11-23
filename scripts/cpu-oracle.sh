#!/bin/sh
# Builds tools/cpu-oracle, this machine's CPU as a test oracle for the lifter.
#
#   scripts/cpu-oracle.sh [output]
#
# Linux x86-64 only. The default output is target/cpu-oracle. No stack
# protector: the signal handlers must run before fs is known to be intact.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/target/cpu-oracle}

mkdir -p "$(dirname "$out")"
cc -O2 -std=c11 -Wall -Wextra -fno-stack-protector "$root/tools/cpu-oracle/cpu_oracle.c" -o "$out"
echo "$out"
