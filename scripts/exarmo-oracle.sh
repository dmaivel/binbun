#!/bin/sh
# Builds tools/exarmo-oracle (exarmo-aarch64 0.4.0, a separate cargo
# workspace, so the main build never compiles exarmo).
#
#   scripts/exarmo-oracle.sh [output]
#
# The default output is target/exarmo-oracle. The A64 decoder's test
# newer_encodings_match_exarmo (crates/binbun-aarch64/tests/oracle.rs)
# runs it as BINBUN_EXARMO_ORACLE.
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
out=${1:-$root/target/exarmo-oracle}
target=${CARGO_TARGET_DIR:-$root/target}/exarmo-oracle-build

cargo build --release --locked --manifest-path "$root/tools/exarmo-oracle/Cargo.toml" \
    --target-dir "$target"
mkdir -p "$(dirname "$out")"
cp "$target/release/exarmo-oracle" "$out"
echo "$out"
