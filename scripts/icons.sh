#!/usr/bin/env bash
# Renders the app icon's PNGs and ICO from its drawings in
# gui/app/assets/logo: binbun-icon-16.svg up to 20 px, binbun-icon-small.svg
# from 21 to 48 px (no stroke, the ears apart, larger eyes) and
# binbun-icon.svg above. Writes
#
#   gui/app/assets/linux/icons/NxN/binbun.png   hicolor sizes 16 to 512
#   gui/app/assets/windows/binbun.ico           16, 20, 24, 32, 40, 48, 64, 256
#
# Those files are checked in and never edited by hand: change a drawing,
# run this, commit both. Needs rsvg-convert (librsvg) and ImageMagick 7
# (magick); the same versions give the same bytes.
#
#   scripts/icons.sh
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
assets=$root/gui/app/assets
logo=$assets/logo
for tool in rsvg-convert magick; do
    command -v "$tool" >/dev/null || { echo "icons.sh: $tool not found" >&2; exit 1; }
done

drawing() { # size: the drawing made for it
    if [ "$1" -le 20 ]; then
        echo "$logo/binbun-icon-16.svg"
    elif [ "$1" -le 48 ]; then
        echo "$logo/binbun-icon-small.svg"
    else
        echo "$logo/binbun-icon.svg"
    fi
}
render() { # size file
    rsvg-convert -w "$1" -h "$1" "$(drawing "$1")" -o "$2"
}

for size in 16 24 32 48 64 128 256 512; do
    mkdir -p "$assets/linux/icons/${size}x$size"
    render "$size" "$assets/linux/icons/${size}x$size/binbun.png"
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
images=()
for size in 16 20 24 32 40 48 64 256; do
    render "$size" "$work/$size.png"
    images+=("$work/$size.png")
done
# 256 stored as PNG (Windows Vista and later), the smaller sizes as
# bitmaps; -strip leaves out dates.
magick "${images[@]}" -strip -define icon:png-compression-size=256 "$assets/windows/binbun.ico"
