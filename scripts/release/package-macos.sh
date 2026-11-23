#!/usr/bin/env bash
# Builds and packs binbun for macOS: binbun-X.Y.Z-TARGET.dmg, holding
# binbun.app (GUI and CLI in one `binbun`: Contents/MacOS/binbun) and a
# link to /Applications.
#
#   scripts/release/package-macos.sh [--target TRIPLE] [--out DIR] [--signatures PACKS]
#
# TARGET: aarch64-apple-darwin or x86_64-apple-darwin (default the
# host's; either builds on either Mac with Xcode's command line tools).
# DIR defaults to target/dist. PACKS: a directory of signature packs
# (*.jsonl.zst) installed with binbun, in Contents/Resources/signatures
# (binbun reads them there). The icon is drawn from the app icon's SVGs
# with sips and iconutil, both part of macOS.
#
# The app is signed ad hoc only (no Developer ID): opened from a
# browser's download, Gatekeeper asks to allow it in System Settings →
# Privacy & Security → Open Anyway; install.sh's copy (curl sets no
# quarantine) opens directly.
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
    *-apple-darwin) ;;
    *) die "$target is not a macOS target" ;;
esac
version=$(release_version)
ensure_target "$target"
out=$(absolute_dir "$out")
reproducible_env
# The oldest macOS the app supports.
export MACOSX_DEPLOYMENT_TARGET=${MACOSX_DEPLOYMENT_TARGET:-12.0}

gui_target_dir=${CARGO_TARGET_DIR:+$CARGO_TARGET_DIR/gui}
gui_target_dir=${gui_target_dir:-$root/gui/target}
mkdir -p "$gui_target_dir"
stage=$(mktemp -d "$gui_target_dir/stage.XXXXXX")
trap 'rm -rf "$stage"' EXIT

(cd "$root/gui" && CARGO_TARGET_DIR=$gui_target_dir cargo build --release --locked -p binbun-gui --bin binbun --target "$target")

app=$stage/dmg/binbun.app
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
install -m 755 "$gui_target_dir/$target/release/binbun" "$app/Contents/MacOS/binbun"
copy_notices "$app/Contents/Resources" app
copy_gui_notices "$app/Contents/Resources"
[ -z "$signatures" ] || copy_signatures "$signatures" "$app/Contents/Resources/signatures"

# The icon: the app icon drawn at each size macOS asks for, the small
# sizes from the drawings made for them (as scripts/icons.sh draws the
# Linux and Windows icons).
logo=$root/gui/app/assets/logo
iconset=$stage/binbun.iconset
mkdir -p "$iconset"
draw() { # size file
    local svg=$logo/binbun-icon.svg
    if [ "$1" -le 20 ]; then svg=$logo/binbun-icon-16.svg; elif [ "$1" -le 48 ]; then svg=$logo/binbun-icon-small.svg; fi
    sips -s format png -z "$1" "$1" "$svg" --out "$iconset/$2" >/dev/null
}
for size in 16 32 128 256 512; do
    draw "$size" "icon_${size}x$size.png"
    draw $((size * 2)) "icon_${size}x${size}@2x.png"
done
iconutil -c icns -o "$app/Contents/Resources/binbun.icns" "$iconset"

cat >"$app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key>
	<string>en</string>
	<key>CFBundleDisplayName</key>
	<string>binbun</string>
	<key>CFBundleExecutable</key>
	<string>binbun</string>
	<key>CFBundleIconFile</key>
	<string>binbun</string>
	<key>CFBundleIdentifier</key>
	<string>org.binbun.binbun</string>
	<key>CFBundleInfoDictionaryVersion</key>
	<string>6.0</string>
	<key>CFBundleName</key>
	<string>binbun</string>
	<key>CFBundlePackageType</key>
	<string>APPL</string>
	<key>CFBundleShortVersionString</key>
	<string>$version</string>
	<key>CFBundleVersion</key>
	<string>$version</string>
	<key>LSApplicationCategoryType</key>
	<string>public.app-category.developer-tools</string>
	<key>LSMinimumSystemVersion</key>
	<string>$MACOSX_DEPLOYMENT_TARGET</string>
	<key>NSHighResolutionCapable</key>
	<true/>
	<key>NSHumanReadableCopyright</key>
	<string>MIT OR Apache-2.0</string>
</dict>
</plist>
EOF
plutil -lint "$app/Contents/Info.plist" >/dev/null

# An ad hoc signature over the whole bundle (Apple silicon runs no
# unsigned code; the linker's signature covers the executable alone).
codesign --force --sign - --timestamp=none "$app"
codesign --verify --strict "$app"

ln -s /Applications "$stage/dmg/Applications"
name=binbun-$version-$target
rm -f "$out/$name.dmg"
hdiutil create -quiet -volname binbun -srcfolder "$stage/dmg" -fs HFS+ -format UDZO -ov "$out/$name.dmg"
echo "$out/$name.dmg"
