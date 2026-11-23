#!/usr/bin/env bash
# The images link previews show for binbun.org (Open Graph and Twitter
# cards, site/templates/base.html and blog-page.html), 1200x630 each, in
# the app's font (IBM Plex Sans) on the site's background:
#
# - site/static/assets/og.png, the landing page's, the download page's and
#   the blog's: the icon, the name and what binbun is on the left, the dark
#   hero screenshot (site/static/assets/preview/one-dark.webp) on the
#   right;
# - site/static/assets/blog/SLUG.png for each post in site/content/blog/:
#   the icon and the name, the post's title, its date. The post's page
#   fails to build without it.
#
# Run it again when the hero or the icon changes, and for a new post or a
# post's new title or date. Needs ImageMagick 7 (`magick`).
#
#   scripts/site/og-image.sh
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
fonts=$root/gui/app/assets/fonts
assets=$root/site/static/assets
command -v magick >/dev/null || { echo "og-image.sh: needs ImageMagick 7 (magick)" >&2; exit 1; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
background='#1d1f24' text='#e8e9eb' muted='#a3a8b0'

# The default card.
magick -background none -density 384 "$assets/binbun-icon.svg" -resize 112x112 "$work/icon.png"
# The screenshot's top left, its corners rounded.
magick "$assets/preview/one-dark.webp" -resize 1000x -crop 820x520+0+0 +repage \
    \( +clone -alpha extract \
        -draw "fill black polygon 0,0 0,14 14,0 fill white circle 14,14 14,0" \
        \( +clone -flip \) -compose Multiply -composite \
        \( +clone -flop \) -compose Multiply -composite \) \
    -alpha off -compose CopyOpacity -composite "$work/shot.png"
magick -size 1200x630 xc:"$background" \
    "$work/shot.png" -geometry +470+150 -composite \
    "$work/icon.png" -geometry +64+150 -composite \
    -font "$fonts/IBMPlexSans-Bold.ttf" -pointsize 76 -fill "$text" -annotate +64+352 'binbun' \
    -font "$fonts/IBMPlexSans-Regular.ttf" -pointsize 30 -fill "$muted" \
    -annotate +64+412 'Interactive disassembler' -annotate +64+452 'and decompiler' \
    -depth 8 -strip "$assets/og.png"
echo "$assets/og.png"

# A front matter value of post $1: the string or bare value of key $2.
front() {
    awk -v key="$2" '
        /^\+\+\+$/ { fences++; if (fences == 2) exit; next }
        fences == 1 && $0 ~ "^" key " *= *" {
            sub("^" key " *= *", ""); gsub(/^"|"$/, ""); print; exit
        }
    ' "$1"
}

# 2026-11-15 as 15 November 2026 (GNU date, else BSD date).
long_date() {
    LC_ALL=C date -d "$1" '+%-d %B %Y' 2>/dev/null ||
        LC_ALL=C date -j -f %Y-%m-%d "$1" '+%-d %B %Y'
}

# Each post's card.
magick -background none -density 384 "$assets/binbun-icon.svg" -resize 64x64 "$work/small-icon.png"
mkdir -p "$assets/blog"
for post in "$root"/site/content/blog/*.md; do
    [ "$(basename "$post")" = _index.md ] && continue
    slug=$(front "$post" slug)
    [ -n "$slug" ] || slug=$(basename "$post" .md)
    title=$(front "$post" title)
    date=$(front "$post" date)
    [ -n "$title" ] && [ -n "$date" ] || { echo "og-image.sh: $post has no title or date" >&2; exit 1; }
    # Three lines of the title at most, smaller when it is long.
    size=80
    [ ${#title} -le 60 ] || size=64
    magick -size 1200x630 xc:"$background" \
        "$work/small-icon.png" -geometry +72+64 -composite \
        -font "$fonts/IBMPlexSans-Medium.ttf" -pointsize 34 -fill "$muted" -annotate +152+108 'binbun' \
        \( -size 1056x330 -background none -font "$fonts/IBMPlexSans-Bold.ttf" -pointsize "$size" \
            -fill "$text" -interline-spacing -6 caption:"$title" \) -geometry +72+190 -composite \
        -font "$fonts/IBMPlexSans-Regular.ttf" -pointsize 28 -fill "$muted" -annotate +72+566 "$(long_date "$date")" \
        -depth 8 -strip "$assets/blog/$slug.png"
    echo "$assets/blog/$slug.png"
done
