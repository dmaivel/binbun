#!/usr/bin/env bash
# Installs cargo-c (cargo cbuild/cinstall, used by package-capi.sh) from
# its release's prebuilt binaries, each checked against the SHA-256
# pinned here, into DIR (default $CARGO_HOME/bin, else ~/.cargo/bin).
# Linux x86_64 and aarch64 (static musl builds), macOS (Apple silicon),
# Windows (x86_64; emulated on ARM64).
#
#   scripts/release/install-cargo-c.sh [DIR]
#
# Elsewhere: cargo install --locked cargo-c@0.10.26
set -euo pipefail

version=0.10.26
dir=${1:-${CARGO_HOME:-$HOME/.cargo}/bin}
# Git Bash: CARGO_HOME is a Windows path.
if command -v cygpath >/dev/null 2>&1; then dir=$(cygpath -u "$dir"); fi

case $(uname -s)-$(uname -m) in
    Linux-x86_64) asset=cargo-c-x86_64-unknown-linux-musl.tar.gz sha256=685fab5a2e1539c5075cea21c42469ee5a489d877dbdbf7adccf4bb631d77545 ;;
    Linux-aarch64) asset=cargo-c-aarch64-unknown-linux-musl.tar.gz sha256=68a45c967438240b64f2806639098c89df676c0152e855f5122cf5173204ce6c ;;
    Darwin-arm64) asset=cargo-c-macos.zip sha256=891ec1f27eb48f24ed615fd52180528c71295a2c9049b306c204e15e53130354 ;;
    MINGW*-* | MSYS*-*) asset=cargo-c-windows-msvc.zip sha256=f6d39f23adc68d669833e2473979a3b923c32cdc35e94d5145593fa1a6e7c812 ;;
    *)
        echo "install-cargo-c.sh: no prebuilt cargo-c for $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL -o "$work/$asset" \
    "https://github.com/lu-zero/cargo-c/releases/download/v$version/$asset"
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$work/$asset" | cut -d ' ' -f 1)
else
    actual=$(shasum -a 256 "$work/$asset" | cut -d ' ' -f 1)
fi
[ "$actual" = "$sha256" ] || {
    echo "install-cargo-c.sh: $asset's SHA-256 is $actual, expected $sha256" >&2
    exit 1
}
mkdir -p "$work/bin" "$dir"
case $asset in
    *.tar.gz) tar -xzf "$work/$asset" -C "$work/bin" ;;
    *.zip) unzip -q "$work/$asset" -d "$work/bin" ;;
esac
for tool in "$work"/bin/cargo-*; do
    install -m 755 "$tool" "$dir/"
done
"$dir/cargo-cinstall" --version
