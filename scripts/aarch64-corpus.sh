#!/usr/bin/env bash
# Fetches the AArch64 benchmark corpus (bench/results/README.md): Debian
# trixie arm64 packages and Node's Windows ARM64 build, from which the files
# below are taken and checked against their SHA-256.
#
# Usage: scripts/aarch64-corpus.sh [--full] [dir]
#   --full  also the larger corpus (libLLVM, hugo, OpenBLAS, node.exe)
#   dir     where the files go (default ~/.cache/binbun-arm64/corpus)
# Needs: curl, bsdtar, sha256sum.
#
# Debian removes superseded package versions from deb.debian.org; if a URL
# is gone, the same file is on snapshot.debian.org under the same name.
set -euo pipefail

full=false
if [[ "${1:-}" == --full ]]; then
    full=true
    shift
fi
dest="${1:-$HOME/.cache/binbun-arm64/corpus}"
debian=https://deb.debian.org/debian/pool/main

# file in the corpus, its SHA-256, the package it comes from
main=(
    "elf/libc6/libc.so.6 70fa4c4cf57eabeb96097cce47582d02379c4cd1de3db3e98ade4dd7089a1b13 $debian/g/glibc/libc6_2.41-12+deb13u4_arm64.deb"
    "elf/libstdc++6/libstdc++.so.6.0.33 fff1f0050a33ddf29c44634c7639ac16e2573a61e3daab4fcc4c007b432ccf19 $debian/g/gcc-14/libstdc++6_14.2.0-19_arm64.deb"
    "elf/libssl3t64/libcrypto.so.3 ad2d83bfb64c15110615fbee4161ee2cbe890abe0c924c459f63f89d4085940d $debian/o/openssl/libssl3t64_3.5.7-1~deb13u2_arm64.deb"
    "elf/bash/bash ccbd5106945d1095474e5ee47317266f5918aa37fc671829192a007918b1413a $debian/b/bash/bash_5.2.37-2+b10_arm64.deb"
)
larger=(
    "elf/libllvm19/libLLVM.so.19.1 deedb2db087ef76313adb278f2f720ee8ddd163ec0ba2e06ab4f69227534664f $debian/l/llvm-toolchain-19/libllvm19_19.1.7-3+b1_arm64.deb"
    "elf/hugo/hugo 77d985f49bdb29b016559aa8e37ef702bb0dc695d8efb087c79f313b522133df $debian/h/hugo/hugo_0.131.0-1_arm64.deb"
    "elf/libopenblas0-pthread/libopenblasp-r0.3.29.so 46b0e90ce26832166420b26e18290022a1c77f241a079ec0c33a2e685e839fff $debian/o/openblas/libopenblas0-pthread_0.3.29+ds-3_arm64.deb"
    "pe/node/node.exe 4c9baa047c4ae555050179f25a63153f1c962af32e2aad97735fb550750c5e7a https://nodejs.org/dist/v26.13.0/node-v26.13.0-win-arm64.zip"
)
files=("${main[@]}")
if $full; then
    files+=("${larger[@]}")
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

for entry in "${files[@]}"; do
    read -r path sha256 url <<<"$entry"
    if [[ -f "$dest/$path" ]] && echo "$sha256  $dest/$path" | sha256sum --check --status; then
        echo "have $path"
        continue
    fi
    unpacked="$work/unpacked"
    rm -rf "$unpacked"
    mkdir -p "$unpacked"
    curl --fail --location --silent --show-error --output "$work/package" "$url"
    if [[ "$url" == *.deb ]]; then
        # A .deb is an ar archive around data.tar.*.
        bsdtar -xf "$work/package" -C "$unpacked"
        bsdtar -xf "$unpacked"/data.tar.* -C "$unpacked"
    else
        bsdtar -xf "$work/package" -C "$unpacked"
    fi
    found=""
    while IFS= read -r -d '' candidate; do
        if echo "$sha256  $candidate" | sha256sum --check --status; then
            found="$candidate"
            break
        fi
    done < <(find "$unpacked" -type f -name "$(basename "$path")" -print0)
    if [[ -z "$found" ]]; then
        echo "no $(basename "$path") with SHA-256 $sha256 in $url" >&2
        exit 1
    fi
    mkdir -p "$(dirname "$dest/$path")"
    cp "$found" "$dest/$path"
    echo "got $path"
done
