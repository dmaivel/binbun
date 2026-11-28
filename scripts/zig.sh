#!/usr/bin/env bash
# Fetches Zig 0.17.1, the version libghostty-vt's source builds with (the
# GUI's terminal, gui/Cargo.toml's ghostty-vt), into gui/target/zig (or DIR),
# its archive checked against the SHA-256 pinned here, and prints the path
# of its `zig`. The GUI's builds find it there (gui/.cargo/config.toml's
# ZIG); set ZIG to use another Zig 0.17. macOS builds take libghostty-vt
# prebuilt and need no Zig. Linux and Windows, x86_64 and aarch64.
#
#   scripts/zig.sh [DIR]
set -euo pipefail

version=0.17.1
root=$(cd "$(dirname "$0")/.." && pwd)
dir=${1:-$root/gui/target/zig}

case $(uname -s)-$(uname -m) in
    Linux-x86_64) asset=zig-x86_64-linux-$version.tar.xz sha256=3581863e3cbcfd0fce0efc682ce7e9e93da96668a977791d356a26d2a7e9b17a ;;
    Linux-aarch64) asset=zig-aarch64-linux-$version.tar.xz sha256=a1546d5646eb184437918d6635ca6b762a0e889eac09cef720ee7a1ed3fe7795 ;;
    MINGW*-x86_64 | MSYS*-x86_64 | CYGWIN*-x86_64) asset=zig-x86_64-windows-$version.zip sha256=b03f477a1943673e02aca0f570e8030dffd536ce1f45cbc4d3326ec31159562e ;;
    MINGW*-aarch64 | MSYS*-aarch64 | CYGWIN*-aarch64 | MINGW*-arm64 | MSYS*-arm64) asset=zig-aarch64-windows-$version.zip sha256=4789895bdb1e312a2ea73b2a7c0a0cc8d2ab62ba6976e834a7c54cf443377c15 ;;
    *)
        echo "zig.sh: no Zig pinned for $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac
name=${asset%.tar.xz}
name=${name%.zip}
case $asset in *.zip) exe=zig.exe ;; *) exe=zig ;; esac

if [ ! -x "$dir/$name/$exe" ]; then
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    curl --proto '=https' --tlsv1.2 -fsSL -o "$work/$asset" "https://ziglang.org/download/$version/$asset"
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$work/$asset" | cut -d ' ' -f 1)
    else
        actual=$(shasum -a 256 "$work/$asset" | cut -d ' ' -f 1)
    fi
    [ "$actual" = "$sha256" ] || {
        echo "zig.sh: $asset's SHA-256 is $actual, expected $sha256" >&2
        exit 1
    }
    mkdir -p "$dir"
    case $asset in
        *.zip) (cd "$dir" && unzip -q "$work/$asset") ;;
        *) tar -xJf "$work/$asset" -C "$dir" ;;
    esac
fi
case $asset in
    # Windows: no link (Git Bash copies the directory), and the path as
    # Windows has it (cargo's build scripts are not Git Bash's); CI sets ZIG.
    *.zip)
        if command -v cygpath >/dev/null 2>&1; then
            cygpath -m "$dir/$name/$exe"
        else
            echo "$dir/$name/$exe"
        fi
        ;;
    # The path gui/.cargo/config.toml gives, whichever Zig this is.
    *)
        ln -sfn "$name" "$dir/current"
        echo "$dir/current/$exe"
        ;;
esac
