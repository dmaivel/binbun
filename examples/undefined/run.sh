#!/bin/sh
# Builds lie and twin, runs each natively (twin pinned to each core type of
# a hybrid Intel processor), then shows what binbun says of them: the C,
# and twin's value on each processor profile.
#
#   sh examples/undefined/run.sh [P-CPU] [E-CPU]    (defaults 0 and 16)
#
# Needs cc, taskset and binbun on PATH (or BINBUN=path/to/binbun).
set -eu
here=$(dirname "$0")
out=${TMPDIR:-/tmp}/binbun-undefined
binbun=${BINBUN:-binbun}
p=${1:-0}
e=${2:-16}
mkdir -p "$out"
cc -o "$out/lie" "$here/lie.s"
cc -o "$out/twin" "$here/twin.s"

echo "lie, natively:          $("$out/lie")"
echo "twin on CPU $p (P-core): $(taskset -c "$p" "$out/twin")"
echo "twin on CPU $e (E-core): $(taskset -c "$e" "$out/twin")"
echo
echo "binbun decompile lie main:"
"$binbun" decompile "$out/lie" main
echo
echo "binbun decompile twin main:"
"$binbun" decompile "$out/twin" main
echo
echo "binbun verify twin main --compare intel-raptor-cove,intel-gracemont:"
# Exit status 1: the processors differ, as this shows.
"$binbun" verify "$out/twin" main --compare intel-raptor-cove,intel-gracemont || [ $? -eq 1 ]
