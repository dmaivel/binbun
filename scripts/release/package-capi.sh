#!/usr/bin/env bash
# Builds and packs binbun's C library, built and laid out by cargo-c
# (`cargo install cargo-c`): libbinbun-X.Y.Z-TARGET.tar.gz (a zip on
# Windows), holding
#
#   include/binbun/{binbun.h,core.h,core.hpp,disasm.h,disasm_generated.h,disasm.hpp}
#   lib/libbinbun.so.0 (.dylib, or bin/binbun.dll with its import
#       library), lib/libbinbun.a (binbun.lib)
#   lib/pkgconfig/binbun.pc (prefix /usr/local: unpack there, or
#       use `pkg-config --define-prefix`)
#   share/doc/libbinbun (licences)
#
#   scripts/release/package-capi.sh [--target TRIPLE] [--out DIR]
#
# TARGET defaults to the host's; DIR to target/dist.
#
# On macOS the library's install name is @rpath/libbinbun.0.dylib,
# so it loads from wherever it is unpacked: link with
# -Wl,-rpath,<its lib directory> (as on Linux outside the loader's path).
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(dirname "$0")/common.sh"

target=
out=$root/target/dist
while [ $# -gt 0 ]; do
    case $1 in
        --target) target=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        *) die "usage: $0 [--target TRIPLE] [--out DIR]" ;;
    esac
done
target=${target:-$(host_target)}
version=$(release_version)
ensure_target "$target"
out=$(absolute_dir "$out")
reproducible_env
case $target in
    *-apple-darwin) export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-11.0} ;;
esac

target_dir=${CARGO_TARGET_DIR:-$root/target}
mkdir -p "$target_dir"
stage=$(mktemp -d "$target_dir/stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

name=libbinbun-$version-$target
# MSYS_NO_PATHCONV: Git Bash, on Windows, would make --prefix=/usr/local
# a Windows path under its own directory, installing beside usr/local.
(cd "$root" && MSYS_NO_PATHCONV=1 cargo cinstall --release --locked -p binbun-capi --target "$target" \
    --prefix=/usr/local --libdir=lib --destdir="$(native_path "$stage/destdir")")
mv "$stage/destdir/usr/local" "$stage/$name"
rm -rf "$stage/destdir"
case $target in
    *-apple-darwin)
        # The file; the shorter names are links to it.
        dylib=$(find "$stage/$name/lib" -type f -name 'libbinbun.*.dylib')
        [ -n "$dylib" ] || die "cargo-c made no libbinbun dylib"
        install_name_tool -id @rpath/libbinbun.0.dylib "$dylib"
        # The linker's ad hoc signature no longer matches.
        codesign --force --sign - "$dylib"
        ;;
esac
copy_notices "$stage/$name/share/doc/libbinbun" capi
case $target in
    *-windows-*)
        zip_dir "$out/$name.zip" "$stage"
        echo "$out/$name.zip"
        ;;
    *)
        tar_gz "$out/$name.tar.gz" "$stage" "$name"
        echo "$out/$name.tar.gz"
        ;;
esac
