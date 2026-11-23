#!/usr/bin/env bash
# Builds and packs binbun for Linux:
#
#   binbun-X.Y.Z-TARGET.tar.gz      the app (GUI and CLI in one `binbun`),
#                                   in Zed's layout: binbun.app/bin/binbun,
#                                   share/applications, share/icons,
#                                   share/doc/binbun (licences)
#   binbun-cli-X.Y.Z-TARGET.tar.gz  the CLI alone (the root workspace's
#                                   `binbun`: no GUI, no window-system
#                                   libraries), for servers and containers
#
#   scripts/release/package-linux.sh [--target TRIPLE] [--cli-only] [--out DIR]
#                                    [--signatures PACKS]
#
# TARGET defaults to the host's; --cli-only builds only the CLI (the musl
# targets have no app). DIR defaults to target/dist. PACKS: a directory
# of signature packs (*.jsonl.zst) installed with binbun, in each archive's
# share/binbun/signatures (binbun reads them there). Run it in the oldest
# glibc the release supports (scripts/release/linux-container.sh does,
# in AlmaLinux 8, glibc 2.28): BINBUN_MAX_GLIBC=2.28 makes the build fail
# if a binary needs a newer glibc symbol than that.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(dirname "$0")/common.sh"

target=
cli_only=
signatures=
out=$root/target/dist
while [ $# -gt 0 ]; do
    case $1 in
        --target) target=${2:?}; shift 2 ;;
        --cli-only) cli_only=1; shift ;;
        --out) out=${2:?}; shift 2 ;;
        --signatures) signatures=${2:?}; shift 2 ;;
        *) die "usage: $0 [--target TRIPLE] [--cli-only] [--out DIR] [--signatures PACKS]" ;;
    esac
done
if [ -n "$signatures" ]; then
    signatures=$(cd "$signatures" && pwd) || die "no directory $signatures"
fi
target=${target:-$(host_target)}
case $target in
    *-linux-gnu) ;;
    *-linux-musl) cli_only=1 ;;
    *) die "$target is not a Linux target" ;;
esac
version=$(release_version)
ensure_target "$target"
out=$(absolute_dir "$out")
reproducible_env

# Both workspaces build a `binbun`: separate target directories.
target_dir=${CARGO_TARGET_DIR:-$root/target}
gui_target_dir=${CARGO_TARGET_DIR:+$CARGO_TARGET_DIR/gui}
gui_target_dir=${gui_target_dir:-$root/gui/target}
mkdir -p "$target_dir"
stage=$(mktemp -d "$target_dir/stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

# Fails if binary $1 needs a glibc newer than BINBUN_MAX_GLIBC.
check_glibc() {
    [ -n "${BINBUN_MAX_GLIBC:-}" ] || return 0
    local newest
    newest=$(objdump -T "$1" | grep -o 'GLIBC_[0-9.]*' | sed 's/GLIBC_//' | sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1)
    if [ -n "$newest" ] && [ "$(printf '%s\n%s\n' "$newest" "$BINBUN_MAX_GLIBC" | sort -t. -k1,1n -k2,2n | tail -n 1)" != "$BINBUN_MAX_GLIBC" ]; then
        die "$1 needs GLIBC_$newest, newer than $BINBUN_MAX_GLIBC"
    fi
    echo "$1: glibc ${newest:-none} or newer"
}

# The CLI alone, from the root workspace.
(cd "$root" && cargo build --release --locked -p binbun-cli --bin binbun --target "$target")
cli=$target_dir/$target/release/binbun
check_glibc "$cli"
name=binbun-cli-$version-$target
mkdir -p "$stage/$name/bin" "$stage/$name/share/doc/binbun"
install -m 755 "$cli" "$stage/$name/bin/binbun"
copy_notices "$stage/$name/share/doc/binbun" cli
[ -z "$signatures" ] || copy_signatures "$signatures" "$stage/$name/share/binbun/signatures"
tar_gz "$out/$name.tar.gz" "$stage" "$name"
echo "$out/$name.tar.gz"

[ -n "$cli_only" ] && exit 0

# The app, from the GUI's workspace.
(cd "$root/gui" && CARGO_TARGET_DIR=$gui_target_dir cargo build --release --locked -p binbun-gui --bin binbun --target "$target")
app=$gui_target_dir/$target/release/binbun
check_glibc "$app"
assets=$root/gui/app/assets
dir=$stage/binbun.app
mkdir -p "$dir/bin" "$dir/share/applications" "$dir/share/doc/binbun" "$dir/share/icons/hicolor/scalable/apps"
install -m 755 "$app" "$dir/bin/binbun"
install -m 644 "$assets/linux/binbun.desktop" "$dir/share/applications/binbun.desktop"
# The icons: scalable, and rendered by scripts/icons.sh (the small sizes
# from the drawings made for them).
install -m 644 "$assets/logo/binbun-icon.svg" "$dir/share/icons/hicolor/scalable/apps/binbun.svg"
for size in 16 24 32 48 64 128 256 512; do
    mkdir -p "$dir/share/icons/hicolor/${size}x$size/apps"
    install -m 644 "$assets/linux/icons/${size}x$size/binbun.png" "$dir/share/icons/hicolor/${size}x$size/apps/binbun.png"
done
copy_notices "$dir/share/doc/binbun" app
copy_gui_notices "$dir/share/doc/binbun"
[ -z "$signatures" ] || copy_signatures "$signatures" "$dir/share/binbun/signatures"
name=binbun-$version-$target
tar_gz "$out/$name.tar.gz" "$stage" binbun.app
echo "$out/$name.tar.gz"
