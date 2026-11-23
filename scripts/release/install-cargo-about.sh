#!/usr/bin/env bash
# Installs cargo-about (third-party-licenses.sh) from its release's
# prebuilt binaries, each checked against the SHA-256 pinned here, into
# DIR (default $CARGO_HOME/bin, else ~/.cargo/bin). Linux x86_64 and
# aarch64 (static musl builds), macOS (Apple silicon).
#
#   scripts/release/install-cargo-about.sh [DIR]
#
# Elsewhere: cargo install --locked --features cli cargo-about@0.9.3
set -euo pipefail

version=0.9.3
dir=${1:-${CARGO_HOME:-$HOME/.cargo}/bin}

case $(uname -s)-$(uname -m) in
    Linux-x86_64) target=x86_64-unknown-linux-musl sha256=3ad1e94ea1e63d69d1961f4fb15ccbbe9575d906111f96d2cb4dce6df48f71b4 ;;
    Linux-aarch64) target=aarch64-unknown-linux-musl sha256=eb4d9ff6ebd2518152a8308729431a04b3836e71d2bd5ead7aea69f91a71162e ;;
    Darwin-arm64) target=aarch64-apple-darwin sha256=45520df8680978a6e7c4023ace0e3f311c73efc208cd68e5a7f4ed4822fa0349 ;;
    *)
        echo "install-cargo-about.sh: no prebuilt cargo-about for $(uname -s) $(uname -m)" >&2
        exit 1
        ;;
esac
asset=cargo-about-$version-$target.tar.gz

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
curl --proto '=https' --tlsv1.2 -fsSL -o "$work/$asset" \
    "https://github.com/EmbarkStudios/cargo-about/releases/download/$version/$asset"
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$work/$asset" | cut -d ' ' -f 1)
else
    actual=$(shasum -a 256 "$work/$asset" | cut -d ' ' -f 1)
fi
[ "$actual" = "$sha256" ] || {
    echo "install-cargo-about.sh: $asset's SHA-256 is $actual, expected $sha256" >&2
    exit 1
}
tar -xzf "$work/$asset" -C "$work"
mkdir -p "$dir"
install -m 755 "$work/cargo-about-$version-$target/cargo-about" "$dir/"
"$dir/cargo-about" --version
