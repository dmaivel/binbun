#!/bin/sh
# Builds tools/cpu-oracle-aarch64, an AArch64 CPU as a test oracle for the
# AArch64 lifter: a static Linux AArch64 binary.
#
#   scripts/cpu-oracle-aarch64.sh [output]
#
# The default output is target/cpu-oracle-aarch64. On an AArch64 Linux host
# it is built with the system compiler (cc, or $CC), elsewhere with
# `zig cc -target aarch64-linux-musl` (or $CC, which must target AArch64
# Linux and link statically); run it there with `qemu-aarch64 -cpu max`.
# No stack protector, general registers only: the signal handlers run after
# the instruction, which may have changed tpidr_el0 and FPCR.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/target/cpu-oracle-aarch64}

if [ -n "${CC:-}" ]; then
    cc=$CC
elif [ "$(uname -m)" = aarch64 ]; then
    cc=cc
else
    cc="zig cc -target aarch64-linux-musl"
fi

mkdir -p "$(dirname "$out")"
# $cc is deliberately split into words (a compiler and its arguments).
# shellcheck disable=SC2086
$cc -O2 -std=c11 -Wall -Wextra -fno-stack-protector -mgeneral-regs-only -static \
    "$root/tools/cpu-oracle-aarch64/cpu_oracle.c" -o "$out"
echo "$out"
