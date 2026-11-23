#!/usr/bin/env bash
# Builds the signature packs installed with binbun, each from pinned
# inputs whose SHA-256 is checked, with its provenance in the pack's header (library,
# version, licence, source and its checksum, each build's toolchain,
# flags and inputs' checksums; every header in OUT/PROVENANCE):
#
#   musl-1.2.5.jsonl.zst  musl 1.2.5 built here from its release tarball
#                         (./configure --disable-shared; make lib/libc.a),
#                         three builds: gcc -O2, gcc -Os, clang -O2.
#                         MIT; the pack carries recordings, not code.
#   glibc-DISTRO.jsonl.zst the libc.a of a distribution's own package, not
#                         a rebuild (the binaries in the wild are linked
#                         against those): Debian stable (13), Ubuntu LTS
#                         (26.04), Fedora (45), Arch Linux. LGPL-2.1+:
#                         recordings only; the header names the exact
#                         source package, its checksum and where it is.
#   rust-std-V.jsonl.zst  the x86_64-unknown-linux-gnu sysroot .rlibs of
#                         the rust-std component rustup installs for
#                         toolchain V (the current stable and the two
#                         before). MIT OR Apache-2.0.
#
# The packs of Microsoft's libraries (scripts/signatures/msvc.sh,
# scripts/signatures/kernel.sh) are made by hand, from libraries no
# script can download, and committed in scripts/signatures/hand-built
# with their SHA-256s (its SHA256SUMS; its README says how each was
# made): --hand-built copies them into OUT, each checked, and lists them
# in OUT/PROVENANCE with the script that made them. The release adds
# them so to the packs it built (.github/workflows/signatures.yml).
#
# Each pack is made as JSON Lines (`sig make --plain`, kept in
# WORK/packs to review) and compressed with `zstd -19 --single-thread`:
# about a sixteenth of the text, a quarter of what binbun's own encoder
# (`sig make` without --plain) gives. The zstd version is in the key and
# in OUT/PROVENANCE's last line.
#
# Usage: scripts/signatures/packs.sh --binbun BIN [--out DIR] [--work DIR] [PACK...]
#        scripts/signatures/packs.sh --key [PACK...]
#        scripts/signatures/packs.sh --hand-built [--out DIR]
#   PACK      musl, glibc-debian, glibc-ubuntu, glibc-fedora, glibc-arch,
#             rust-1.100.0, rust-1.99.0, rust-1.98.1 (default: all)
#   --binbun  the binbun that makes the packs (`binbun sig make`)
#   --out     where the packs go (default target/signatures)
#   --work    downloads and builds (default target/signatures-work); kept,
#             so a second run downloads and builds nothing, and
#             scripts/signatures/corpus.sh links its programs against the
#             libraries built or extracted there
#   --key     prints what the packs are made from besides binbun (this
#             script, with every input's pin; zstd's version; for musl
#             the compilers' versions): the release workflow caches them
#             by it
#   --hand-built  the packs made by hand copied into OUT, each refused
#             unless its SHA-256 is the one hand-built/SHA256SUMS lists,
#             and OUT/PROVENANCE written again for every pack in OUT
#
# The same inputs, compilers, zstd and binbun give byte-identical packs.
# Needs: curl, sha256sum, tar, bsdtar (libarchive: .deb, .rpm,
# .pkg.tar.zst), zstd, make, gcc and clang (musl).
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
out=$root/target/signatures
work=$root/target/signatures-work
binbun=
key=
hand=
packs=()
while [ $# -gt 0 ]; do
    case $1 in
        --binbun) binbun=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        --work) work=${2:?}; shift 2 ;;
        --key) key=1; shift ;;
        --hand-built) hand=1; shift ;;
        -*) echo "usage: $0 --binbun BIN [--out DIR] [--work DIR] [PACK...] | --key | --hand-built [--out DIR]" >&2; exit 2 ;;
        *) packs+=("$1"); shift ;;
    esac
done

# Pinned inputs: name, URL, SHA-256.
musl_version=1.2.5
musl_url=https://musl.libc.org/releases/musl-$musl_version.tar.gz
musl_sha256=a9a118bbe84d8764da0ea0d28b3ab3fae8477fc7e4085d90102b8596fc7c75e4
musl_notice="Copyright © 2005-2020 Rich Felker, et al. (musl's COPYRIGHT file; MIT licence)"
# The musl builds: id, compiler, CFLAGS.
musl_builds=("gcc-O2 gcc -O2" "gcc-Os gcc -Os" "clang-O2 clang -O2")

# Each distribution's glibc: the binary package holding libc.a (URL,
# SHA-256, libc.a's path in it), and the corresponding source package
# (name, URL, SHA-256). URLs that stay: Debian's snapshot archive,
# Launchpad's librarian, Fedora's Koji, the Arch Linux Archive; the
# Arch source is the package's PKGBUILD at its release tag (it pins
# glibc's git commit 16be1518495f1fa05481b0182c4e4c24927c62df and its
# patches' checksums).
glibc_distros=(debian ubuntu fedora arch)
# shellcheck disable=SC2034 # read by name (local -n) in build_glibc
glibc_debian=(
    "Debian 13 (trixie)" 2.41-12+deb13u4
    https://snapshot.debian.org/archive/debian/20260912T075541Z/pool/main/g/glibc/libc6-dev_2.41-12%2Bdeb13u4_amd64.deb
    1fda734dabcd80b77266a09ab62b0f1e3e16d8091db62899890b2200745632a2
    usr/lib/x86_64-linux-gnu
    glibc_2.41-12+deb13u4.dsc
    https://snapshot.debian.org/archive/debian/20260912T075541Z/pool/main/g/glibc/glibc_2.41-12%2Bdeb13u4.dsc
    0915324aa646bb99abfaa9aa6ecb734b30babd28454a3e51f3152912370fbd3e
)
# shellcheck disable=SC2034
glibc_ubuntu=(
    "Ubuntu 26.04 LTS (resolute)" 2.43-2ubuntu2.7
    https://launchpad.net/ubuntu/+archive/primary/+files/libc6-dev_2.43-2ubuntu2.7_amd64.deb
    338a4f0c8fc38f1002447096c62cb412cfa3a5eab034857aec33e343d429551d
    usr/lib/x86_64-linux-gnu
    glibc_2.43-2ubuntu2.7.dsc
    https://launchpad.net/ubuntu/+archive/primary/+files/glibc_2.43-2ubuntu2.7.dsc
    f2ef1d49c67efaf54870b87f858ec8b7a97fa1d3be31ce1b91314697b3f080d5
)
# shellcheck disable=SC2034
glibc_fedora=(
    "Fedora 45" 2.44-2.fc45
    https://kojipkgs.fedoraproject.org/packages/glibc/2.44/2.fc45/x86_64/glibc-static-2.44-2.fc45.x86_64.rpm
    a852e26c6405f5c50c4b4207aeae9eabbbb9e2078e185ace2f17b3d182f73b83
    usr/lib64
    glibc-2.44-2.fc45.src.rpm
    https://kojipkgs.fedoraproject.org/packages/glibc/2.44/2.fc45/src/glibc-2.44-2.fc45.src.rpm
    4fc86035b84047b31de4b4ab0e5faa1b79095cb0f95f99b120d3f386954e91c8
)
# shellcheck disable=SC2034
glibc_arch=(
    "Arch Linux" 2.44+r24+g16be1518495f-1
    https://archive.archlinux.org/packages/g/glibc/glibc-2.44%2Br24%2Bg16be1518495f-1-x86_64.pkg.tar.zst
    5db2283f5b46b6114d06b4bc71fcf8ede5f1a04fcccb4d307048fcdc4e501d93
    usr/lib
    "glibc 2.44+r24+g16be1518495f-1 PKGBUILD"
    https://gitlab.archlinux.org/archlinux/packaging/packages/glibc/-/raw/2.44+r24+g16be1518495f-1/PKGBUILD
    700a847bbf7b078d4718b0268ae55c50a115a3c0700bd3c05b9a22fc546b4a12
)

# Rust: version, rustc's version line, the rust-std component (URL,
# SHA-256) and the std library's source (rust-src: URL, SHA-256), as the
# release's channel manifest (static.rust-lang.org/dist/channel-rust-V.toml)
# lists them.
rust_versions=(1.100.0 1.99.0 1.98.1)
# shellcheck disable=SC2034 # read by name (local -n) in build_rust
rust_1_100_0=(
    "rustc 1.100.0 (0ef1bc386 2026-11-09)"
    https://static.rust-lang.org/dist/2026-11-12/rust-std-1.100.0-x86_64-unknown-linux-gnu.tar.gz
    61eb09d68b338e230d698716927bd4623049c9910ef4a4972e66d763d66ed9e1
    https://static.rust-lang.org/dist/2026-11-12/rust-src-1.100.0.tar.gz
    f37ba90547b1075da3a0953742cab9f9e33b5c08bce747bb0ff8382537b2fa8c
)
# shellcheck disable=SC2034
rust_1_99_0=(
    "rustc 1.99.0 (b940084d7 2026-09-28)"
    https://static.rust-lang.org/dist/2026-10-01/rust-std-1.99.0-x86_64-unknown-linux-gnu.tar.gz
    1dcaa01beb6bc78fdb13815b4f15214719167c58e3d79fbdf214591f8c195ee1
    https://static.rust-lang.org/dist/2026-10-01/rust-src-1.99.0.tar.gz
    82b978093b33c71bcbe69005b92181bfb76d3d0e434ef303e637812e21badcd7
)
# shellcheck disable=SC2034
rust_1_98_1=(
    "rustc 1.98.1 (48a229cea 2026-09-01)"
    https://static.rust-lang.org/dist/2026-09-03/rust-std-1.98.1-x86_64-unknown-linux-gnu.tar.gz
    eddab0358cbd12aeb897716aab00d1db7b59696e85b9ac4982e72259a9a976b1
    https://static.rust-lang.org/dist/2026-09-03/rust-src-1.98.1.tar.gz
    411c3dccf3782ed6eb784357999cd1bffeb65a6dd55196817992a6421c0f9689
)
# The sysroot's .rlibs a program links that are not std's own crates'
# test harness or compiler plugins.
rust_skip='^lib(test|proc_macro|getopts|rustc_std_workspace_[a-z]+)-'

# The compilers the musl builds use, by version.
compilers() {
    gcc --version | head -n 1
    clang --version | head -n 1
}

# The packs' compression: zstd's level, single-threaded (the same bytes
# for the same text and zstd).
zstd_args=(-19 --single-thread)

# The packs made by hand: the files scripts/signatures/hand-built/SHA256SUMS
# lists with their SHA-256s (a new version replaces its pack there, with
# no change here to rebuild the cached packs for).
hand_dir=$root/scripts/signatures/hand-built
mapfile -t hand_built < <(awk '{ print $2 }' "$hand_dir/SHA256SUMS")

# hand_maker PACK: the script that made the hand-built pack PACK.
hand_maker() {
    case $1 in
        msvc-crt-*) echo scripts/signatures/msvc.sh ;;
        wdk-km-*) echo scripts/signatures/kernel.sh ;;
        *) echo "$0: $1: no script here makes it" >&2; exit 1 ;;
    esac
}

# Every pack's header in OUT (its provenance), one JSON line each, a pack
# made by hand's preceded by the script that made it and its SHA-256;
# then how the packs built here are compressed (the hand-built ones' zstd
# is in hand-built/README.md).
provenance() {
    local pack header made name
    for pack in "$out"/*.jsonl.zst; do
        [ -f "$pack" ] || continue
        header=$(head -n 1 < <(zstd -dcq "$pack"))
        made=
        for name in "${hand_built[@]}"; do
            if [ "$name" = "$(basename "$pack")" ]; then
                made=$(hand_maker "$name")
            fi
        done
        if [ -n "$made" ]; then
            echo "{\"hand_built\":\"$made\",\"sha256\":\"$(sha256sum "$pack" | cut -d' ' -f1)\",${header#\{}"
        else
            echo "$header"
        fi
    done
    echo "{\"compressed\":\"zstd ${zstd_args[*]}\",\"zstd\":\"$(zstd -qV)\"}"
}

if [ -n "$key" ]; then
    sha256sum "$0" | cut -d' ' -f1
    echo "zstd $(zstd -qV)"
    if [ ${#packs[@]} -eq 0 ] || [[ " ${packs[*]} " == *" musl "* ]]; then
        compilers
    fi
    exit 0
fi

if [ -n "$hand" ]; then
    [ ${#hand_built[@]} -gt 0 ] || { echo "$0: $hand_dir/SHA256SUMS lists no pack" >&2; exit 1; }
    mkdir -p "$out"
    out=$(cd "$out" && pwd)
    for name in "${hand_built[@]}"; do
        hand_maker "$name" >/dev/null
        sha256=$(awk -v name="$name" '$2 == name { print $1 }' "$hand_dir/SHA256SUMS")
        install -m 644 "$hand_dir/$name" "$out/$name"
        if ! echo "$sha256  $out/$name" | sha256sum --check --status; then
            rm -f "$out/$name"
            echo "$0: $hand_dir/$name: its SHA-256 is not $sha256 (SHA256SUMS)" >&2
            exit 1
        fi
        echo "$out/$name"
    done
    provenance >"$out/PROVENANCE"
    exit 0
fi

[ -n "$binbun" ] || { echo "$0: --binbun BIN is needed" >&2; exit 2; }
binbun=$(cd "$(dirname "$binbun")" && pwd)/$(basename "$binbun")
[ ${#packs[@]} -gt 0 ] || {
    packs=(musl)
    for distro in "${glibc_distros[@]}"; do packs+=("glibc-$distro"); done
    for version in "${rust_versions[@]}"; do packs+=("rust-$version"); done
}
mkdir -p "$out" "$work/downloads" "$work/packs"
out=$(cd "$out" && pwd)
work=$(cd "$work" && pwd)

# compress PACK: the plain pack PACK (in work/packs) compressed into
# out/PACK.zst, the pack installed.
compress() {
    zstd "${zstd_args[@]}" --quiet --force "$1" -o "$out/$(basename "$1").zst"
}

# fetch URL SHA256 FILE: FILE (in work/downloads) downloaded from URL
# unless already there with that checksum; its path printed.
fetch() {
    local url=$1 sha256=$2 file=$work/downloads/$3
    if ! echo "$sha256  $file" | sha256sum --check --status 2>/dev/null; then
        curl --fail --location --silent --show-error --retry 3 --output "$file.part" "$url"
        echo "$sha256  $file.part" | sha256sum --check --status || {
            echo "$0: $url: SHA-256 is not $sha256" >&2
            rm -f "$file.part"
            exit 1
        }
        mv "$file.part" "$file"
    fi
    echo "$file"
}

# musl: the tarball built three ways in work/musl/ID (libc.a, crt files,
# headers: corpus.sh links against them), each a build of one pack; each
# build's pack alone kept in work/musl for the evaluation's other-flags
# and other-compiler cases (corpus.sh).
build_musl() {
    local tarball id cc flags pack=$work/packs/musl-$musl_version.jsonl dir first=1
    local options=(--library musl --version "$musl_version" --licence MIT --notice "$musl_notice"
        --source "musl-$musl_version.tar.gz" --url "$musl_url" --sha256 "$musl_sha256")
    tarball=$(fetch "$musl_url" "$musl_sha256" "musl-$musl_version.tar.gz")
    rm -f "$pack"
    for build in "${musl_builds[@]}"; do
        read -r id cc flags <<<"$build"
        dir=$work/musl/$id
        if [ ! -f "$dir/lib/libc.a" ]; then
            rm -rf "$dir" "$dir.src"
            mkdir -p "$dir.src"
            tar -xzf "$tarball" -C "$dir.src" --strip-components=1
            (
                cd "$dir.src"
                CC=$cc CFLAGS=$flags ./configure --disable-shared --prefix="$dir" >/dev/null
                make -j"${CARGO_BUILD_JOBS:-$(nproc)}" lib/libc.a lib/crt1.o lib/crti.o lib/crtn.o >/dev/null
                mkdir -p "$dir/lib"
                cp lib/libc.a lib/crt1.o lib/crti.o lib/crtn.o "$dir/lib/"
                # The headers as an install lays them out, for corpus.sh.
                make install-headers >/dev/null
            )
            rm -rf "$dir.src"
        fi
        local build_options=(--build "$id" --toolchain "$($cc --version | head -n 1)"
            --flags "CFLAGS=$flags ./configure --disable-shared; make lib/libc.a")
        "$binbun" sig make "${options[@]}" "${build_options[@]}" "$dir/lib/libc.a" \
            --plain -o "$work/musl/musl-$musl_version-$id.jsonl"
        if [ -n "$first" ]; then
            cp "$work/musl/musl-$musl_version-$id.jsonl" "$pack"
            first=
        else
            "$binbun" sig make "${options[@]}" "${build_options[@]}" --add-to "$pack" \
                "$dir/lib/libc.a" --plain -o "$pack"
        fi
    done
    compress "$pack"
}

# glibc of DISTRO: libc.a (and the crt files, for corpus.sh) taken out of
# the distribution's package into work/glibc/DISTRO.
build_glibc() {
    local distro=$1 name version url sha256 path source source_url source_sha256 package dir file
    local -n pins=glibc_$distro
    name=${pins[0]} version=${pins[1]} url=${pins[2]} sha256=${pins[3]} path=${pins[4]}
    source=${pins[5]} source_url=${pins[6]} source_sha256=${pins[7]}
    file=$(basename "$url")
    file=${file//%2B/+}
    package=$(fetch "$url" "$sha256" "$file")
    dir=$work/glibc/$distro
    rm -rf "$dir"
    mkdir -p "$dir"
    case $file in
        *.deb) bsdtar -xOf "$package" 'data.tar*' | bsdtar -xf - -C "$dir" "$path/libc.a" "$path/crt1.o" "$path/crti.o" "$path/crtn.o" ;;
        *.rpm) bsdtar -xf "$package" -C "$dir" "./$path/libc.a" ;;
        *) bsdtar -xf "$package" -C "$dir" "$path/libc.a" "$path/crt1.o" "$path/crti.o" "$path/crtn.o" ;;
    esac
    mv "$dir/$path"/* "$dir/"
    "$binbun" sig make --library glibc --version "$version" --licence LGPL-2.1-or-later \
        --notice "The GNU C Library, as $name packages it: recordings of its functions' behaviour (no code); its corresponding source is $source ($source_url)" \
        --source "$source" --url "$source_url" --sha256 "$source_sha256" \
        --build "$distro" --toolchain "$name's build ($file, SHA-256 $sha256)" \
        "$dir/libc.a" --plain -o "$work/packs/glibc-$distro.jsonl"
    compress "$work/packs/glibc-$distro.jsonl"
}

# Rust std of VERSION: the rust-std component's .rlibs.
build_rust() {
    local version=$1 rustc url sha256 src_url src_sha256 tarball dir rlibs=()
    local -n pins=rust_${version//./_}
    rustc=${pins[0]} url=${pins[1]} sha256=${pins[2]} src_url=${pins[3]} src_sha256=${pins[4]}
    tarball=$(fetch "$url" "$sha256" "$(basename "$url")")
    dir=$work/rust/$version
    rm -rf "$dir"
    mkdir -p "$dir"
    tar -xzf "$tarball" -C "$dir" --strip-components=1 --wildcards '*/lib/rustlib/x86_64-unknown-linux-gnu/lib/*.rlib'
    while IFS= read -r rlib; do
        [[ $(basename "$rlib") =~ $rust_skip ]] || rlibs+=("$rlib")
    done < <(find "$dir" -name '*.rlib' | LC_ALL=C sort)
    "$binbun" sig make --library rust-std --version "$version" --licence "MIT OR Apache-2.0" \
        --notice "The Rust standard library (rust-lang/rust): Copyright The Rust Project Developers; MIT or Apache-2.0" \
        --source "rust-src-$version.tar.gz" --url "$src_url" --sha256 "$src_sha256" \
        --build x86_64-unknown-linux-gnu \
        --toolchain "$rustc (rust-std-$version-x86_64-unknown-linux-gnu.tar.gz, SHA-256 $sha256)" \
        --flags "as distributed (rustup's rust-std component)" \
        "${rlibs[@]}" --plain -o "$work/packs/rust-std-$version.jsonl"
    compress "$work/packs/rust-std-$version.jsonl"
}

for pack in "${packs[@]}"; do
    echo "== $pack" >&2
    case $pack in
        musl) build_musl ;;
        glibc-*) build_glibc "${pack#glibc-}" ;;
        rust-*) build_rust "${pack#rust-}" ;;
        *) echo "$0: no pack $pack" >&2; exit 2 ;;
    esac
done
provenance >"$out/PROVENANCE"
