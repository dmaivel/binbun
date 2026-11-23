#!/bin/bash
# The decompiler benchmark, whole: the corpus fetched (once) into CORPUS,
# every tool run and scored, the report and its chart written.
#
#   bench/decompile/run.sh CORPUS [WORK]
#
# WORK (default bench/results/decompile-work) keeps each tool's output and
# each verdict; a second run reuses them (delete a file there to redo its
# step). The tools are found as bench/src/bin/decompile/main.rs says
# (BINBUN and BINBUN_COMMIT, IDA_DIR, GHIDRA_DIR, ANGR_PYTHON,
# GHIDRA_PROJECTS). Pinned to CPUs 16-31 like the other benchmarks' runs;
# set CPUS to change that. The behaviour test samples 500 functions per
# file.
#
# With PRIVATE set, the run is repeated with Hex-Rays and Binary Ninja
# (`--private`) into bench/results/private/, which is not tracked: their
# licences restrict publishing their results (docs/benchmarks.md). The
# other tools' outputs are reused from WORK.
set -euo pipefail

corpus=${1:?usage: run.sh CORPUS [WORK]}
bench=$(cd "$(dirname "$0")/.." && pwd)
work=${2:-$bench/results/decompile-work}
cpus=${CPUS:-16-31}

"$bench/decompile/corpus.sh" "$corpus"
corpus=$(cd "$corpus" && pwd)
mkdir -p "$work"
work=$(cd "$work" && pwd)
cd "$bench"
cargo build --release --bin decompile
run() { taskset -c "$cpus" cargo run -q --release --bin decompile -- "$@" --work "$work"; }
measure() {
    run quality --corpus "$corpus" "$@"
    run behaviour --corpus "$corpus" --sample 500 "$@"
    run speed /usr/lib/wine/x86_64-windows/ntdll.dll "$@"
}
measure
python3 plot.py
if [ -n "${PRIVATE:-}" ]; then
    measure --private
    python3 plot.py results/private
fi
