#!/bin/sh
# Prepares an AlmaLinux 8 container (glibc 2.28, the oldest glibc
# binbun's Linux builds support) to build binbun: the C toolchain, the
# window-system headers the GUI links (xcb, xkbcommon), and rustup, whose
# toolchain is then the one rust-toolchain.toml pins. Run as root in the
# container; the release workflow's Linux jobs and
# scripts/release/linux-container.sh both use it.
#
#   scripts/release/container-setup.sh
#
# rustup-init is checked against its SHA-256 before it runs. CARGO_HOME and
# RUSTUP_HOME are where rustup goes (default /usr/local/cargo and
# /usr/local/rustup); add $CARGO_HOME/bin to PATH afterwards.
set -eu

rustup_version=1.29.3
case $(uname -m) in
    x86_64) arch=x86_64 sha256=b1c8cb14e30889e7e2999e6b69e62d9e9b9ffc0f4df8180564d306d9680e6c55 ;;
    aarch64) arch=aarch64 sha256=9f608c142e0e38a78957d0661ba1dfaf0b6fb37184cfaa4b9a0aa57af6184282 ;;
    *) echo "container-setup.sh: no rustup-init pinned for $(uname -m)" >&2; exit 1 ;;
esac

# libxkbcommon-x11-devel is in PowerTools.
dnf -y -q install dnf-plugins-core
dnf -q config-manager --set-enabled powertools
dnf -y -q install gcc gcc-c++ make binutils git findutils diffutils which tar gzip xz util-linux \
    pkgconf-pkg-config fontconfig-devel libxcb-devel libxkbcommon-devel libxkbcommon-x11-devel
dnf -q clean all

export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}" RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"
if [ ! -x "$CARGO_HOME/bin/rustup" ]; then
    # rustup-init knows itself by its file name.
    dir=$(mktemp -d)
    init=$dir/rustup-init
    curl --proto '=https' --tlsv1.2 -fsSL -o "$init" \
        "https://static.rust-lang.org/rustup/archive/$rustup_version/$arch-unknown-linux-gnu/rustup-init"
    echo "$sha256  $init" | sha256sum -c -
    chmod +x "$init"
    "$init" -y -q --no-modify-path --profile minimal --default-toolchain none
    rm -rf "$dir"
fi
