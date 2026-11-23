#!/bin/sh
# Reads one release's section of CHANGELOG.md, the heading
# "## vX.Y.Z (YYYY-MM-DD)" and what follows up to the next "## ".
#
#   scripts/release/changelog.sh notes VERSION     the section's text (the
#                                                  release notes), without
#                                                  its heading, each
#                                                  paragraph and list item
#                                                  on one line
#   scripts/release/changelog.sh date VERSION      its date
#   scripts/release/changelog.sh security VERSION  exit 0 if it has a
#                                                  "### Security" group
#
# Fails, saying why, when the version has no section, no date, or only
# blank lines and comments: the release workflow then refuses the tag.
# CHANGELOG (default CHANGELOG.md at the tree's root) names another file.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
file=${CHANGELOG:-$root/CHANGELOG.md}
command=${1:-}
version=${2:-}
version=${version#v}
[ -n "$version" ] || {
    echo "usage: $0 notes|date|security VERSION" >&2
    exit 2
}

# The section: its heading's date on the first line, then its lines with
# HTML comments removed and the blank lines at both ends trimmed.
section=$(awk -v heading="## v$version" '
    function flush() { while (blank > 0) { print ""; blank-- } }
    index($0, heading) == 1 {
        rest = substr($0, length(heading) + 1)
        if (rest == "" || rest ~ /^[ \t]/) {
            found = 1
            date = rest
            sub(/^[ \t]*\(/, "", date); sub(/\).*$/, "", date)
            print "date " date
            next
        }
    }
    found && /^## / { exit }
    !found { next }
    comment { if (/-->/) { sub(/.*-->/, ""); comment = 0 } else next }
    /<!--/ {
        line = $0
        while (match(line, /<!--.*-->/)) line = substr(line, 1, RSTART - 1) substr(line, RSTART + RLENGTH)
        if (line ~ /<!--/) { sub(/<!--.*/, "", line); comment = 1 }
        $0 = line
    }
    /^[ \t]*$/ { if (printed) blank++; next }
    { flush(); print; printed = 1 }
' "$file")

case $section in
    "date "*) ;;
    *)
        echo "changelog.sh: $file has no section \"## v$version (date)\"" >&2
        exit 1
        ;;
esac
date=$(printf '%s\n' "$section" | sed -n '1s/^date //p')
notes=$(printf '%s\n' "$section" | sed '1d')

# The notes with each paragraph and list item on one line, as GitHub
# shows them best: a line that starts no block (a heading, list item,
# quote, table row or code fence) continues the one before, unless that
# is a heading or table row; code blocks are left as they are.
unwrapped() {
    awk '
        function flush() { if (held) { print current; held = 0 } }
        /^[ \t]*```/ { flush(); print; fenced = !fenced; next }
        fenced { print; next }
        /^[ \t]*$/ { flush(); print; next }
        {
            text = $0
            sub(/^[ \t]+/, "", text)
            starts = text ~ /^(#|[-*+] |[0-9]+[.)] |>|\|)/
            if (held && !starts && current !~ /^[ \t]*(#|\|)/) {
                current = current " " text
                next
            }
            flush()
            current = $0
            held = 1
        }
        END { flush() }
    '
}

case $command in
    notes)
        [ -n "$notes" ] || {
            echo "changelog.sh: v$version's section in $file is empty" >&2
            exit 1
        }
        printf '%s\n' "$notes" | unwrapped
        ;;
    date)
        printf '%s\n' "$date" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || {
            echo "changelog.sh: v$version's heading has no date (\"## v$version (YYYY-MM-DD)\")" >&2
            exit 1
        }
        printf '%s\n' "$date"
        ;;
    security)
        printf '%s\n' "$notes" | grep -q '^### Security[[:space:]]*$'
        ;;
    *)
        echo "usage: $0 notes|date|security VERSION" >&2
        exit 2
        ;;
esac
