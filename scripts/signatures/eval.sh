#!/usr/bin/env bash
# The signatures evaluation in one step, for a binbun whose signature
# code changed: every pack made again by it (packs.sh; the libraries it
# downloaded and built are kept in
# WORK, so only `binbun sig make` runs again), the corpus built unless
# it is there (corpus.sh: its programs do not depend on binbun), and
# `binbun sig eval` run on it. Exits as sig eval does: non-zero if a
# case misses a target.
#
# Usage: scripts/signatures/eval.sh --binbun BIN [--packs DIR] [--work DIR]
#                                   [--corpus DIR] [--sweep|--no-sweep]
#   --packs   packs.sh's --out (default target/signatures)
#   --work    packs.sh's --work (default target/signatures-work)
#   --corpus  corpus.sh's --out (default target/signatures-corpus)
#   --sweep, --no-sweep   passed to sig eval (default: a session's)
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
packs=$root/target/signatures
work=$root/target/signatures-work
corpus=$root/target/signatures-corpus
binbun=
sweep=()
while [ $# -gt 0 ]; do
    case $1 in
        --binbun) binbun=${2:?}; shift 2 ;;
        --packs) packs=${2:?}; shift 2 ;;
        --work) work=${2:?}; shift 2 ;;
        --corpus) corpus=${2:?}; shift 2 ;;
        --sweep | --no-sweep) sweep=("$1"); shift ;;
        *) echo "usage: $0 --binbun BIN [--packs DIR] [--work DIR] [--corpus DIR] [--sweep|--no-sweep]" >&2; exit 2 ;;
    esac
done
[ -n "$binbun" ] || { echo "$0: --binbun BIN is needed" >&2; exit 2; }

"$root/scripts/signatures/packs.sh" --binbun "$binbun" --out "$packs" --work "$work"
[ -f "$corpus/cases" ] ||
    "$root/scripts/signatures/corpus.sh" --packs "$packs" --work "$work" --out "$corpus"
"$binbun" sig eval "$corpus/cases" --packs "$packs" "${sweep[@]}"
