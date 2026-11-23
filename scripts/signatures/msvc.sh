#!/usr/bin/env bash
# Builds the MSVC runtime signature pack by hand, from a pinned Visual
# Studio toolset the maker has installed (Microsoft's libraries cannot be
# downloaded by a script): recordings of the functions' behaviour, no
# code.
#
#   msvc-crt-14.51.36231.jsonl.zst
#       the /MT static runtime of MSVC 14.51.36231 and the Universal CRT
#       of Windows SDK 10.0.26100.0, one build: libcmt.lib,
#       libvcruntime.lib (VC/Tools/MSVC/14.51.36231/lib/x64), libucrt.lib
#       (Windows Kits/10/Lib/10.0.26100.0/ucrt/x64) and libcpmt.lib (the
#       C++ standard library), each checked against its SHA-256 below.
#
# The pack is made as JSON Lines (`sig make --plain`, kept in WORK to
# review) and compressed as packs.sh compresses the others (`zstd -19
# --single-thread`) into OUT, where packs.sh's PROVENANCE then lists its
# header. The same inputs, binbun and zstd give the same bytes. It takes
# hours (11,000 functions, a quarter of a million pairs whose code fits
# each other's recordings): BINBUN_THREADS (default 32) threads.
# The pack released is the one committed in scripts/signatures/hand-built
# (its README, SHA256SUMS), which the release adds to the packs it builds.
#
# Usage: scripts/signatures/msvc.sh --binbun BIN --vs ROOT [--out DIR] [--work DIR]
#   --binbun  the binbun that makes the pack (`binbun sig make`)
#   --vs      the folder holding VC/Tools/MSVC/14.51.36231 and
#             Windows Kits/10/Lib/10.0.26100.0 (a Visual Studio install,
#             or an `xwin`-style copy of one)
#   --out     where the pack goes (default target/signatures)
#   --work    where the plain pack is kept (default target/signatures-work)
#
# Needs: sha256sum, zstd.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/target/signatures
work=$root/target/signatures-work
binbun=
vs=
while [ $# -gt 0 ]; do
    case $1 in
        --binbun) binbun=${2:?}; shift 2 ;;
        --vs) vs=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        --work) work=${2:?}; shift 2 ;;
        *) echo "usage: $0 --binbun BIN --vs ROOT [--out DIR] [--work DIR]" >&2; exit 2 ;;
    esac
done
[ -n "$binbun" ] && [ -n "$vs" ] || {
    echo "usage: $0 --binbun BIN --vs ROOT [--out DIR] [--work DIR]" >&2
    exit 2
}

msvc=14.51.36231
sdk=10.0.26100.0
# The inputs, in the order the pack is made from: path under ROOT, SHA-256.
inputs=(
    "VC/Tools/MSVC/$msvc/lib/x64/libcmt.lib d4cc4c224455825dec1669f9ad6a9872a4f5b37ed1daae1fd0b9044d7650d908"
    "VC/Tools/MSVC/$msvc/lib/x64/libvcruntime.lib f0a898588ecb26fe4c7530b2495a6fe5e768856309a33391702a3cbcb72b0589"
    "Windows Kits/10/Lib/$sdk/ucrt/x64/libucrt.lib c3a20426b5142bfd0848468a3b95c47440759f0391ef2764e5020672811803cb"
    "VC/Tools/MSVC/$msvc/lib/x64/libcpmt.lib 96f3a2e1113ae8884f459e679a38a35cab542013229a9e6106f58382a6fb47c8"
)
files=()
for input in "${inputs[@]}"; do
    path=$vs/${input% *}
    sha256=${input##* }
    echo "$sha256  $path" | sha256sum --check --status || {
        echo "$0: $path: missing, or its SHA-256 is not $sha256" >&2
        exit 1
    }
    files+=("$path")
done

mkdir -p "$out" "$work/packs"
pack=$work/packs/msvc-crt-$msvc.jsonl
BINBUN_THREADS=${BINBUN_THREADS:-32} "$binbun" sig make --library msvc-crt --version "$msvc" \
    --licence LicenseRef-Microsoft-Visual-Studio \
    --notice "Microsoft Visual C++ runtime (MSVC $msvc) and Universal CRT (Windows SDK $sdk): recordings of their functions' behaviour, no code; made from the maker's own Visual Studio" \
    --build "msvc-$msvc-sdk-$sdk" --toolchain "MSVC $msvc, Windows SDK $sdk" \
    --flags "/MT static libraries (libcmt, libvcruntime, libucrt, libcpmt)" \
    "${files[@]}" --plain -o "$pack"
zstd -19 --single-thread --quiet --force "$pack" -o "$out/$(basename "$pack").zst"
echo "$out/$(basename "$pack").zst"
