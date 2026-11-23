#!/usr/bin/env bash
# Builds the Windows kernel signature pack by hand, from the static
# libraries of a pinned Windows Driver Kit the maker has installed
# (Microsoft's libraries cannot be downloaded by a script): recordings of
# the functions' behaviour, no code.
#
#   wdk-km-10.0.28000.0.jsonl.zst
#       the code drivers link statically from WDK 10.0.28000.0
#       (Lib/10.0.28000.0/km/x64), each library checked against its
#       SHA-256 below, in two builds:
#       wdk-10.0.28000.0-fastfail  the kernel C runtime (libcntpr.lib), the
#           GS cookie and control-flow guard support drivers for Windows 8
#           and later link (BufferOverflowFastFailK.lib), ntstrsafe.lib,
#           wdmsec.lib (IoCreateDeviceSecure), aux_klib.lib, procgrp.lib,
#           iointex.lib, rtlver.lib, volatileaccessk.lib, usbdex.lib,
#           scsiwmi.lib, stdunk.lib, and KMDF 1.35's entry stub
#           (Lib/wdf/kmdf/x64/1.35/WdfDriverEntry.lib: FxDriverEntry,
#           which a function calling __security_init_cookie and the
#           driver's DriverEntry cannot otherwise be told from)
#       wdk-10.0.28000.0-legacy-gs  the GS support of drivers for earlier
#           Windows (BufferOverflowK.lib), which defines the same functions
#           as BufferOverflowFastFailK.lib with other code
#   The kit's other libraries are import libraries (ntoskrnl.lib, hal.lib:
#   their functions are in the kernel) or a class of driver's own.
#
# The pack is made as JSON Lines (`sig make --plain`, kept in WORK to
# review) and compressed as packs.sh compresses the others (`zstd -19
# --single-thread`) into OUT, where packs.sh's PROVENANCE then lists its
# header. The same inputs, binbun and zstd give the same bytes; it takes
# about half a minute.
# The pack released is the one committed in scripts/signatures/hand-built
# (its README, SHA256SUMS), which the release adds to the packs it builds.
#
# Usage: scripts/signatures/kernel.sh --binbun BIN --wdk ROOT [--out DIR] [--work DIR]
#   --binbun  the binbun that makes the pack (`binbun sig make`)
#   --wdk     the kit's folder holding Lib/10.0.28000.0/km/x64 and
#             Lib/wdf/kmdf/x64/1.35 (C:\Program Files (x86)\Windows Kits\10,
#             or a copy of those folders)
#   --out     where the pack goes (default target/signatures)
#   --work    where the plain pack is kept (default target/signatures-work)
#
# Needs: sha256sum, zstd.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/target/signatures
work=$root/target/signatures-work
binbun=
wdk=
usage="usage: $0 --binbun BIN --wdk ROOT [--out DIR] [--work DIR]"
while [ $# -gt 0 ]; do
    case $1 in
        --binbun) binbun=${2:?}; shift 2 ;;
        --wdk) wdk=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        --work) work=${2:?}; shift 2 ;;
        *) echo "$usage" >&2; exit 2 ;;
    esac
done
[ -n "$binbun" ] && [ -n "$wdk" ] || { echo "$usage" >&2; exit 2; }

version=10.0.28000.0
km=Lib/$version/km/x64
# Each build's inputs, in the order the pack is made from: path under
# ROOT, SHA-256.
fastfail=(
    "$km/libcntpr.lib b020fd3cd5d8868b5feea6fdf358007278840d571ae9e5b09094fa447eee996e"
    "$km/BufferOverflowFastFailK.lib 99958def9a7e9bb56395a2bdbce9aea08a6c32c38e92f307798fb72d503253d0"
    "$km/ntstrsafe.lib 97c20b35e104f94c1c0900bfa912bd07cb4e0cf009533b28beb5fff9b61eaa9e"
    "$km/wdmsec.lib 5b26eb210a4dcdbcb2a5d5b725b4f6adfece48345a5f42ec41979bf30121015d"
    "$km/aux_klib.lib 24f262ec06d730e48b4aeb307f1b324a2535344f9125633500a11dd42bf5eba6"
    "$km/procgrp.lib 8c9adfb66142a636574904f0ce1cc50d98b35f8edfd84205ddc5f0d6d98dcc0b"
    "$km/iointex.lib 9f0a471399895ac4e828e4e62136a4276759ca591ebef9a95d5d383966fcce4f"
    "$km/rtlver.lib 70c3948d27324d332b907da14d4194e100658efd4389df659f9696965e481397"
    "$km/volatileaccessk.lib c1c73701a6b01139b0d4625e558c860d03ec4f5da09b5793c125aed735a64f0d"
    "$km/usbdex.lib 1d02be0ffc5e500adbb778b96a050f4fa050a742ce1e9c57c1d28414c6510cd4"
    "$km/scsiwmi.lib 8fb6e6af183c4432d90f2bee38a40cd4e3a9bf647d3bf0d6ff05b847be6ddca5"
    "$km/stdunk.lib e95b97d1e390b529b9447688927ad9ee3a9d09e29bd4e9c3069d0d3cfb8a40c5"
    "Lib/wdf/kmdf/x64/1.35/WdfDriverEntry.lib aac59b0a2d71087d1964da02426f7fa8e335b124e0e33f39683174a0429691d9"
)
legacy=(
    "$km/BufferOverflowK.lib 4ac0fc42fa3bee428126531fcb687bae9bd0a1b59a65e32ec2762ac1d259a2c0"
)

# The paths of the inputs listed, each checked. Windows' file names are
# not case-sensitive, a copy's may be: the name is matched as such.
checked() {
    local input path sha256 found
    for input in "$@"; do
        path=${input% *}
        sha256=${input##* }
        found=$(find "$wdk/$(dirname "$path")/" -maxdepth 1 -iname "$(basename "$path")" -print -quit 2>/dev/null)
        if [ -z "$found" ] || ! echo "$sha256  $found" | sha256sum --check --status; then
            echo "$0: $wdk/$path: missing, or its SHA-256 is not $sha256" >&2
            exit 1
        fi
        echo "$found"
    done
}
mapfile -t fastfail_files < <(checked "${fastfail[@]}")
mapfile -t legacy_files < <(checked "${legacy[@]}")
[ ${#fastfail_files[@]} -eq ${#fastfail[@]} ] && [ ${#legacy_files[@]} -eq ${#legacy[@]} ] || exit 1

mkdir -p "$out" "$work/packs"
pack=$work/packs/wdk-km-$version.jsonl
make=(
    --library wdk-km --version "$version"
    --licence LicenseRef-Microsoft-WDK
    --notice "Windows Driver Kit $version kernel-mode static libraries: recordings of their functions' behaviour, no code; made from the maker's own WDK"
    --toolchain "WDK $version (km/x64), KMDF 1.35"
)
export BINBUN_THREADS=${BINBUN_THREADS:-32}
"$binbun" sig make "${make[@]}" --build "wdk-$version-fastfail" \
    --flags "kernel-mode static libraries (BufferOverflowFastFailK)" \
    "${fastfail_files[@]}" --plain -o "$work/packs/wdk-km-$version-fastfail.jsonl"
"$binbun" sig make "${make[@]}" --build "wdk-$version-legacy-gs" \
    --flags "kernel-mode GS support for Windows before 8 (BufferOverflowK)" \
    --add-to "$work/packs/wdk-km-$version-fastfail.jsonl" \
    "${legacy_files[@]}" --plain -o "$pack"
rm "$work/packs/wdk-km-$version-fastfail.jsonl"
zstd -19 --single-thread --quiet --force "$pack" -o "$out/$(basename "$pack").zst"
echo "$out/$(basename "$pack").zst"
