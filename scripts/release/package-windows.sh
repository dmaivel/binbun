#!/usr/bin/env bash
# Builds and packs binbun for Windows: binbun-X.Y.Z-TARGET.zip, holding
# binbun.exe, the app (a GUI program: no console window; it runs the
# commands too), bin\binbun.exe, the command (binbun-cli, a console
# program, for PATH; asked for the GUI, it starts ..\binbun.exe), and the
# licences. Portable, the C runtime linked into both, so no Visual C++
# redistributable is needed.
#
#   scripts/release/package-windows.sh [--target TRIPLE] [--out DIR] [--signatures PACKS]
#
# Runs in Git Bash with the MSVC toolchain. TARGET: x86_64-pc-windows-msvc
# or aarch64-pc-windows-msvc (default the host's); DIR defaults to
# target/dist. PACKS: a directory of signature packs (*.jsonl.zst) installed
# with binbun, in signatures\ beside the app (both executables read them
# there). Zipped with 7-Zip (on GitHub's Windows images), else zip.
#
# The icon (gui/app/assets/windows/binbun.ico) is linked into the app by
# the build itself (gui/app/build.rs), as in any cargo build for Windows.
#
# Unsigned: SmartScreen shows "Windows protected your PC" on first run
# (More info → Run anyway).
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(dirname "$0")/common.sh"

target=
signatures=
out=$root/target/dist
while [ $# -gt 0 ]; do
    case $1 in
        --target) target=${2:?}; shift 2 ;;
        --out) out=${2:?}; shift 2 ;;
        --signatures) signatures=${2:?}; shift 2 ;;
        *) die "usage: $0 [--target TRIPLE] [--out DIR] [--signatures PACKS]" ;;
    esac
done
if [ -n "$signatures" ]; then
    signatures=$(cd "$signatures" && pwd) || die "no directory $signatures"
fi
target=${target:-$(host_target)}
case $target in
    *-pc-windows-msvc) ;;
    *) die "$target is not a Windows (MSVC) target" ;;
esac
version=$(release_version)
ensure_target "$target"
out=$(absolute_dir "$out")
reproducible_env
# The C runtime linked statically.
export RUSTFLAGS="$RUSTFLAGS -C target-feature=+crt-static"

# Both workspaces build a `binbun`: separate target directories.
target_dir=${CARGO_TARGET_DIR:-$root/target}
gui_target_dir=${CARGO_TARGET_DIR:+$CARGO_TARGET_DIR/gui}
gui_target_dir=${gui_target_dir:-$root/gui/target}
mkdir -p "$gui_target_dir"
stage=$(mktemp -d "$gui_target_dir/stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

# The command, from the root workspace.
(cd "$root" && cargo build --release --locked -p binbun-cli --bin binbun --target "$target")
# The app, from the GUI's workspace.
(cd "$root/gui" && CARGO_TARGET_DIR=$(native_path "$gui_target_dir") cargo build --release --locked -p binbun-gui --bin binbun --target "$target")

name=binbun-$version-$target
mkdir -p "$stage/bin"
cp "$gui_target_dir/$target/release/binbun.exe" "$stage/binbun.exe"
cp "$target_dir/$target/release/binbun.exe" "$stage/bin/binbun.exe"

# The app and the command are built from two workspaces, each its own
# Cargo.lock: both lists.
copy_notices "$stage" app cli
copy_gui_notices "$stage"
[ -z "$signatures" ] || copy_signatures "$signatures" "$stage/signatures"
zip_dir "$out/$name.zip" "$stage"
echo "$out/$name.zip"
