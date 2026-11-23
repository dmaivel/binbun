#!/bin/sh
# Builds tools/llvm-oracle against the installed LLVM (found with llvm-config).
#
#   scripts/llvm-oracle.sh [output]
#
# The default output is target/llvm-oracle. The A64 decoder's oracle tests
# and their allow-lists (crates/binbun-aarch64/tests/oracle.rs) are
# written for LLVM 22, so another major version is refused: point
# LLVM_CONFIG at an LLVM 22 llvm-config. To move the tests to a new LLVM,
# set LLVM_ORACLE_ANY_VERSION=1 and update the allow-lists and this check.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/target/llvm-oracle}
config=${LLVM_CONFIG:-llvm-config}
expected=22

version=$("$config" --version)
if [ "${version%%.*}" != "$expected" ] && [ -z "${LLVM_ORACLE_ANY_VERSION:-}" ]; then
    echo "llvm-oracle.sh: $config is LLVM $version; the oracle tests need LLVM $expected" \
        "(set LLVM_CONFIG to its llvm-config)" >&2
    exit 1
fi

mkdir -p "$(dirname "$out")"
# shellcheck disable=SC2046 # llvm-config prints several flags.
cc -O2 -std=c99 $("$config" --cflags) "$root/tools/llvm-oracle/oracle.c" \
    $("$config" --ldflags) $("$config" --libs) -Wl,-rpath,"$("$config" --libdir)" -o "$out"
echo "$out (LLVM $version)"
