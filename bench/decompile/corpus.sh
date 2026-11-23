#!/bin/bash
# The decompiler benchmark's corpus, fetched once into DIR and checked
# against its SHA-256 sums:
#
#   bench/decompile/corpus.sh DIR
#
# - DIR/bash: Debian 12's bash (5.2.15-2+b7, amd64; the binary
#   scripts/preview.sh shows), its debug file (bash-dbgsym), its source
#   with Debian's patches applied (src/), and bash's own test suite (tests/)
#   with the helpers it runs (recho, zecho, printenv, xcase) built.
# - DIR/libc: Arch's glibc 2.44+r50 (the build the gates' libc pair is
#   from: libc.so.6, its debug file, ld-linux-x86-64.so.2, the source the
#   debug package carries under src/) and bash (the same Debian binary,
#   its interpreter and library path set to this glibc with patchelf), the
#   program whose test suite exercises this libc.
# - DIR/decompilebench: DecompileBench's headers for Hex-Rays, Ghidra and
#   angr (fix/*/defs.h, fix/hexrays/mmx.h) at a pinned commit. The
#   repository states no licence, so they are fetched, not vendored.
#
# The glibc packages are taken from GLIBC_PACKAGES (a directory holding
# both, as ~/.cache/binbun-truth-data/glibc-r50 does) when set, else
# fetched from the Arch Linux Archive.
#
# Requires: curl, ar, tar with xz and zstd, sha256sum, patch, gcc, patchelf,
# objcopy.
set -euo pipefail

dir=${1:?usage: corpus.sh DIR}
mkdir -p "$dir"
dir=$(cd "$dir" && pwd)
downloads=$dir/downloads
mkdir -p "$downloads"

# fetch NAME SHA256 URL...: DIR/downloads/NAME, from the first URL that
# serves it with that SHA-256.
fetch() {
  local name=$1 sum=$2 url
  shift 2
  local file=$downloads/$name
  if [[ -f $file ]] && [[ $(sha256sum <"$file") == "$sum  -" ]]; then
    return
  fi
  for url in "$@"; do
    if curl -fsSL --retry 3 -o "$file.part" "$url" &&
      [[ $(sha256sum <"$file.part") == "$sum  -" ]]; then
      mv "$file.part" "$file"
      return
    fi
  done
  rm -f "$file.part"
  echo "corpus.sh: cannot fetch $name with SHA-256 $sum" >&2
  exit 1
}

snapshot=https://snapshot.debian.org/archive
fetch bash.deb d3c65202568384a588ea32017b243fe64ca054943a008cba4e5bd8f9e79975c4 \
  "$snapshot/debian/20240331T210805Z/pool/main/b/bash/bash_5.2.15-2%2Bb7_amd64.deb"
fetch bash-dbgsym.deb dfa4a241ee19e8f74af52b650077e7a2e0ea41983e195f43f7c301c307ff5922 \
  "$snapshot/debian-debug/20240331T213543Z/pool/main/b/bash/bash-dbgsym_5.2.15-2%2Bb7_amd64.deb"
fetch bash_5.2.15.orig.tar.gz 7a315bc0e9d90713159e4390ec1096a41e4f33cd8cc3d1a749a8e5ad56600f51 \
  "$snapshot/debian/20230102T153446Z/pool/main/b/bash/bash_5.2.15.orig.tar.gz"
fetch bash_5.2.15-2.debian.tar.xz 998f8ea5b754a734ae7d8306e149c43d713ddfcf49623a036004b729237dbcca \
  "$snapshot/debian/20230102T153446Z/pool/main/b/bash/bash_5.2.15-2.debian.tar.xz"

glibc=glibc-2.44%2Br50%2Bg1848099f063e-1-x86_64.pkg.tar.zst
glibc_debug=glibc-debug-2.44%2Br50%2Bg1848099f063e-1-x86_64.pkg.tar.zst
if [[ -n ${GLIBC_PACKAGES:-} ]]; then
  cp -n "$GLIBC_PACKAGES/$glibc" "$GLIBC_PACKAGES/$glibc_debug" "$downloads/" || true
fi
archive=https://archive.archlinux.org/packages/g
fetch "$glibc" e8e4d50d45cb2bd21c9f7eabacc6a01bd5eb93dbd476f3f44d44038fc1eba417 \
  "$archive/glibc/$glibc"
fetch "$glibc_debug" 50acdee68f7ab32154821dca489b29686da047a06470f52269e7b64383fb3d3f \
  "$archive/glibc-debug/$glibc_debug"

commit=761c6513b10344f502474f3e5e78c74fd89ab839
raw=https://raw.githubusercontent.com/vul337/DecompileBench/$commit/fix
fetch hexrays-defs.h 2687a89df38484b25937c73044f39bb62fc49fc4f817a18a2600048025c7abca "$raw/hexrays/defs.h"
fetch hexrays-mmx.h 94fb1bcdd89e7189984b1cf1d069f2ebe7bc9ebc4b29f3b8c399ee007c159810 "$raw/hexrays/mmx.h"
fetch ghidra-defs.h daf2689664e13d90e96e0fb00fa33464c6919f9207561b370523928ed318b157 "$raw/ghidra/defs.h"
fetch angr-defs.h 048c1253577f9a7b2df89669422058eb89e8ec169e5b7ed1264aa6160b59e20a "$raw/angr/defs.h"

# check FILE SHA256: the file extracted is the one expected.
check() {
  [[ $(sha256sum <"$1") == "$2  -" ]] || {
    echo "corpus.sh: $1 is not the expected file" >&2
    exit 1
  }
}

work=$dir/extract
rm -rf "$work"
mkdir -p "$work"

# bash: the binary, its debug file (by its build ID), its patched source.
mkdir -p "$dir/bash"
(cd "$work" && ar x "$downloads/bash.deb" data.tar.xz && tar xJf data.tar.xz ./bin/bash && rm data.tar.xz)
install -m 755 "$work/bin/bash" "$dir/bash/bash"
check "$dir/bash/bash" a4b895f98db75079f2af6e510c95db0d5c5d596e448bf3fe689d0bfdd182e28e
(cd "$work" && ar x "$downloads/bash-dbgsym.deb" data.tar.xz && tar xJf data.tar.xz && rm data.tar.xz)
install -m 644 "$work/usr/lib/debug/.build-id/f6/101dbf7496e744703ecab8c33c2cc348805f7f.debug" "$dir/bash/bash.debug"
check "$dir/bash/bash.debug" c2a64d7a618dac0ad027a54143e9b265391415b6d8e45c2091b83f9c840b8ada
# Its sections are compressed (zlib), which the debug-information reader
# does not read.
objcopy --decompress-debug-sections "$dir/bash/bash.debug"
rm -rf "$dir/bash/src"
tar xzf "$downloads/bash_5.2.15.orig.tar.gz" -C "$work"
mv "$work/bash-5.2.15" "$dir/bash/src"
tar xJf "$downloads/bash_5.2.15-2.debian.tar.xz" -C "$dir/bash/src"
while read -r name; do
  [[ -z $name || $name == \#* ]] && continue
  patch -d "$dir/bash/src" -p1 -s <"$dir/bash/src/debian/patches/$name"
done <"$dir/bash/src/debian/patches/series"

# bash's test suite, with the helpers its tests run, built as its
# Makefile would (support/*.c, without bash's configure: a config.h with
# what they test for).
rm -rf "$dir/bash/tests"
cp -r "$dir/bash/src/tests" "$dir/bash/tests"
mkdir -p "$work/config"
printf '#define HAVE_STRING_H 1\n#define HAVE_STDLIB_H 1\n#define HAVE_UNISTD_H 1\n#define HAVE_LOCALE_H 1\n#define PROTOTYPES 1\n#define __PROTOTYPES 1\n' >"$work/config/config.h"
for helper in recho zecho printenv xcase; do
  gcc -std=gnu89 -O2 -w -DHAVE_CONFIG_H -I"$work/config" -I"$dir/bash/src" -I"$dir/bash/src/include" \
    -o "$dir/bash/tests/$helper" "$dir/bash/src/support/$helper.c"
done

# glibc: the library, its debug file, the loader and the source.
mkdir -p "$dir/libc"
tar -I zstd -xf "$downloads/$glibc" -C "$work" usr/lib/libc.so.6 usr/lib/ld-linux-x86-64.so.2
tar -I zstd -xf "$downloads/$glibc_debug" -C "$work" usr/lib/debug/usr/lib/libc.so.6.debug usr/src/debug/glibc/glibc
install -m 755 "$work/usr/lib/libc.so.6" "$dir/libc/libc.so.6"
check "$dir/libc/libc.so.6" 02c8c3d06180beee9c7d0392aa85736c7d19f274a81e7f8f0b3d9e28e0641524
install -m 755 "$work/usr/lib/ld-linux-x86-64.so.2" "$dir/libc/ld-linux-x86-64.so.2"
check "$dir/libc/ld-linux-x86-64.so.2" f5e11cc62f8f2c24dff532982559f4303dba3b17e7450551372a88c8e7ea8757
install -m 644 "$work/usr/lib/debug/usr/lib/libc.so.6.debug" "$dir/libc/libc.so.6.debug"
check "$dir/libc/libc.so.6.debug" 9af842d74dabd58b9389ac41060ad28f2ed7f3997a943d0422f8cfe9c119bed3
rm -rf "$dir/libc/src"
mv "$work/usr/src/debug/glibc/glibc" "$dir/libc/src"
cp "$dir/bash/bash" "$dir/libc/bash"
patchelf --set-interpreter "$dir/libc/ld-linux-x86-64.so.2" --set-rpath "$dir/libc" "$dir/libc/bash"

# DecompileBench's headers, as its evaluate_rsr.py finds them (-I fix/TOOL).
for tool in hexrays ghidra angr; do
  mkdir -p "$dir/decompilebench/$tool"
  cp "$downloads/$tool-defs.h" "$dir/decompilebench/$tool/defs.h"
done
cp "$downloads/hexrays-mmx.h" "$dir/decompilebench/hexrays/mmx.h"

rm -rf "$work"
echo "corpus in $dir"
