#!/bin/sh
# Makes release X.Y.Z's install.sh from the template
# (scripts/release/install.sh): the version and the SHA-256 of every file
# it may install (the Linux tar.gz files and the macOS dmgs) written in,
# taken from the release's SHA256SUMS.
#
#   scripts/release/make-install-sh.sh X.Y.Z SHA256SUMS > install.sh
#
# Fails if SHA256SUMS lists none of those files or a line is malformed.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
version=${1:?usage: $0 X.Y.Z SHA256SUMS}
version=${version#v}
sums=${2:?usage: $0 X.Y.Z SHA256SUMS}

awk -v version="$version" '
    BEGIN { pattern = version; gsub(/\./, "\\.", pattern) }
    FNR == NR {
        if (NF != 2 || $1 !~ /^[0-9a-f]+$/ || length($1) != 64) {
            printf "make-install-sh.sh: malformed line %d of SHA256SUMS: %s\n", FNR, $0 > "/dev/stderr"
            failed = 1
            exit 1
        }
        name = $2
        sub(/^\*/, "", name)
        if (name ~ ("^binbun-(cli-)?" pattern "-[a-z0-9_]+-unknown-linux-(gnu|musl)\\.tar\\.gz$") ||
            name ~ ("^binbun-" pattern "-[a-z0-9_]+-apple-darwin\\.dmg$")) {
            arms = arms sprintf("        %s) echo %s ;;\n", name, $1)
            count++
        }
        next
    }
    /^[[:space:]]*# @CHECKSUMS@$/ {
        if (count == 0) {
            print "make-install-sh.sh: SHA256SUMS lists no file install.sh installs" > "/dev/stderr"
            failed = 1
            exit 1
        }
        printf "%s", arms
        next
    }
    { gsub(/@VERSION@/, version); print }
    END { if (failed) exit 1 }
' "$sums" "$here/install.sh"
