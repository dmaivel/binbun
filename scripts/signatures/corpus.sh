#!/usr/bin/env bash
# Builds the signatures evaluation's corpus and its cases for
# `binbun sig eval`: each program with symbols (the answers) and stripped
# (what is matched).
#
#   musl/     wc (corpus/wc.c), Lua 5.4.7's interpreter, zlib 1.3.1's
#             minigzip, and whole (wc linked with every member of libc.a),
#             each linked statically against each musl build packs.sh
#             made (gcc -O2, gcc -Os, clang -O2); the programs' own code
#             compiled by gcc -O2
#   glibc/    wc and minigzip linked statically against each
#             distribution's libc.a (packs.sh took them out of the
#             packages)
#   rust/     corpus/wc.rs and corpus/freq.rs built by each Rust
#             toolchain packs.sh made a std pack of (rustc -O; rustup
#             installs a missing toolchain, minimal profile)
#   cases     the cases: every program against the shipped packs (the
#             same builds as the packs': class same, or rust-n), and
#             against one build's pack: musl's other flags and other
#             compiler, Rust std one and two toolchains apart
#
# Usage: scripts/signatures/corpus.sh [--packs DIR] [--work DIR] [--out DIR]
#   --packs  packs.sh's --out (default target/signatures)
#   --work   packs.sh's --work (default target/signatures-work)
#   --out    the corpus (default target/signatures-corpus)
# Then: binbun sig eval OUT/cases --packs DIR
# (scripts/signatures/eval.sh makes the packs again, builds the corpus if
# it is not there, and runs that: one step after binbun's signature code
# changed.)
#
# Needs: packs.sh run first (all packs), curl, sha256sum, tar, gcc,
# strip, rustup.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
packs=$root/target/signatures
work=$root/target/signatures-work
out=$root/target/signatures-corpus
while [ $# -gt 0 ]; do
    case $1 in
        --packs) packs=${2:?}; shift 2 ;;
        --work) work=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        *) echo "usage: $0 [--packs DIR] [--work DIR] [--out DIR]" >&2; exit 2 ;;
    esac
done
mkdir -p "$out" "$work/downloads"
packs=$(cd "$packs" && pwd)
work=$(cd "$work" && pwd)
out=$(cd "$out" && pwd)
corpus=$root/scripts/signatures/corpus

lua_url=https://www.lua.org/ftp/lua-5.4.7.tar.gz
lua_sha256=9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30
zlib_url=https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
zlib_sha256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
musl_version=1.2.5
musl_builds=(gcc-O2 gcc-Os clang-O2)
glibc_distros=(debian ubuntu fedora arch)
rust_versions=(1.100.0 1.99.0 1.98.1)

# fetch URL SHA256: the file downloaded into work/downloads unless there
# with that checksum; its path printed.
fetch() {
    local url=$1 sha256=$2 file
    file=$work/downloads/$(basename "$1")
    if ! echo "$sha256  $file" | sha256sum --check --status 2>/dev/null; then
        curl --fail --location --silent --show-error --retry 3 --output "$file.part" "$url"
        echo "$sha256  $file.part" | sha256sum --check --status || {
            echo "$0: $url: SHA-256 is not $sha256" >&2
            exit 1
        }
        mv "$file.part" "$file"
    fi
    echo "$file"
}

# The programs' sources, unpacked once.
src=$out/src
rm -rf "$src"
mkdir -p "$src"
tar -xzf "$(fetch "$lua_url" "$lua_sha256")" -C "$src"
tar -xzf "$(fetch "$zlib_url" "$zlib_sha256")" -C "$src"
lua_sources=()
for file in "$src"/lua-5.4.7/src/*.c; do
    [ "$(basename "$file")" = luac.c ] || lua_sources+=("$file")
done
zlib_sources=()
for name in adler32 compress crc32 deflate gzclose gzlib gzread gzwrite infback inffast inflate inftrees trees uncompr zutil; do
    zlib_sources+=("$src/zlib-1.3.1/$name.c")
done

# objects DIR CFLAGS...: the programs' objects compiled by gcc -O2 into
# DIR (wc.o, lua/*.o, minigzip/*.o) with the include flags given.
objects() {
    local dir=$1 file
    shift
    rm -rf "$dir"
    mkdir -p "$dir/lua" "$dir/minigzip"
    gcc -O2 "$@" -c "$corpus/wc.c" -o "$dir/wc.o"
    for file in "${lua_sources[@]}"; do
        gcc -O2 -DLUA_USE_POSIX "$@" -c "$file" -o "$dir/lua/$(basename "$file" .c).o"
    done
    for file in "${zlib_sources[@]}" "$src/zlib-1.3.1/test/minigzip.c"; do
        # As zlib's ./configure finds a POSIX system.
        gcc -O2 -DHAVE_UNISTD_H -DHAVE_STDARG_H -I"$src/zlib-1.3.1" "$@" -c "$file" \
            -o "$dir/minigzip/$(basename "$file" .c).o"
    done
}

# program NAME: NAME (with symbols) stripped to NAME.stripped.
stripped() {
    strip -o "$1.stripped" "$1"
}

cases=$out/cases.part
cat >"$cases" <<'EOF'
# binbun sig eval cases (scripts/signatures/corpus.sh):
# NAME CLASS PACKS STRIPPED ANSWERS; PACKS: shipped (sig eval's --packs)
# or pack files.
EOF

# musl: each program against each build.
mkdir -p "$out/musl"
objects "$out/musl/obj" -nostdinc -isystem "$work/musl/gcc-O2/include" -isystem "$(gcc -print-file-name=include)"
for build in "${musl_builds[@]}"; do
    lib=$work/musl/$build/lib
    link=(gcc -static -nostdlib -nostartfiles "$lib/crt1.o" "$lib/crti.o")
    end=("$lib/libc.a" -lgcc "$lib/crtn.o")
    "${link[@]}" "$out/musl/obj/wc.o" "${end[@]}" -o "$out/musl/wc-$build"
    "${link[@]}" "$out/musl/obj/lua"/*.o "${end[@]}" -o "$out/musl/lua-$build"
    "${link[@]}" "$out/musl/obj/minigzip"/*.o "${end[@]}" -o "$out/musl/minigzip-$build"
    "${link[@]}" "$out/musl/obj/wc.o" -Wl,--whole-archive "$lib/libc.a" -Wl,--no-whole-archive \
        -lgcc "$lib/crtn.o" -o "$out/musl/whole-$build"
    for program in wc lua minigzip whole; do
        stripped "$out/musl/$program-$build"
        echo "$program-musl-$build same shipped musl/$program-$build.stripped musl/$program-$build" >>"$cases"
    done
done

# glibc: wc and minigzip against each distribution's libc.a; the crt
# files of its package, or this host's where the package has none
# (Fedora's glibc-static).
mkdir -p "$out/glibc"
objects "$out/glibc/obj"
for distro in "${glibc_distros[@]}"; do
    dir=$work/glibc/$distro
    crt() {
        if [ -f "$dir/$1" ]; then echo "$dir/$1"; else gcc -print-file-name="$1"; fi
    }
    link=(gcc -static -nostdlib -nostartfiles "$(crt crt1.o)" "$(crt crti.o)" "$(gcc -print-file-name=crtbeginT.o)")
    # shellcheck disable=SC2054 # the linker's options are comma-separated
    end=(-Wl,--start-group "$dir/libc.a" -lgcc -lgcc_eh -Wl,--end-group "$(gcc -print-file-name=crtend.o)" "$(crt crtn.o)")
    "${link[@]}" "$out/glibc/obj/wc.o" "${end[@]}" -o "$out/glibc/wc-$distro"
    "${link[@]}" "$out/glibc/obj/minigzip"/*.o "${end[@]}" -o "$out/glibc/minigzip-$distro"
    for program in wc minigzip; do
        stripped "$out/glibc/$program-$distro"
        echo "$program-glibc-$distro same shipped glibc/$program-$distro.stripped glibc/$program-$distro" >>"$cases"
    done
done

# Rust: each program by each toolchain.
mkdir -p "$out/rust"
for version in "${rust_versions[@]}"; do
    rustup run "$version" rustc --version >/dev/null 2>&1 ||
        rustup toolchain install "$version" --profile minimal --no-self-update >/dev/null
    for program in wc freq; do
        rustup run "$version" rustc --edition 2021 -O "$corpus/$program.rs" -o "$out/rust/$program-$version"
        stripped "$out/rust/$program-$version"
        echo "$program-rust-$version rust-n shipped rust/$program-$version.stripped rust/$program-$version" >>"$cases"
    done
done

# One build's pack: musl's other flags and other compiler.
one_pack() { # CLASS PACK PROGRAM-DIR BUILD
    local class=$1 pack=$2 dir=$3 build=$4 program
    for program in wc lua minigzip whole; do
        [ -f "$out/$dir/$program-$build" ] || continue
        echo "$program-$build-by-$(basename "$pack" .jsonl) $class $pack $dir/$program-$build.stripped $dir/$program-$build" >>"$cases"
    done
}
one_pack flags "$work/musl/musl-$musl_version-gcc-O2.jsonl" musl gcc-Os
one_pack flags "$work/musl/musl-$musl_version-gcc-Os.jsonl" musl gcc-O2
one_pack compiler "$work/musl/musl-$musl_version-gcc-O2.jsonl" musl clang-O2
one_pack compiler "$work/musl/musl-$musl_version-clang-O2.jsonl" musl gcc-O2
# Rust std one toolchain apart (either way) and two.
for case in "rust-n1 1.99.0 1.100.0" "rust-n1 1.98.1 1.99.0" "rust-n1 1.100.0 1.99.0" "rust-n2 1.98.1 1.100.0"; do
    read -r class pack version <<<"$case"
    for program in wc freq; do
        echo "$program-rust-$version-by-std-$pack $class $packs/rust-std-$pack.jsonl.zst rust/$program-$version.stripped rust/$program-$version" >>"$cases"
    done
done
mv "$cases" "$out/cases"
rm -rf "$src" "$out/musl/obj" "$out/glibc/obj"
echo "$out/cases"
