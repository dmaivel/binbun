#!/usr/bin/env bash
# Builds the ground-truth corpus for `binbun eval types`: programs with many
# structs, compiled -O2 -g so their DWARF says what each variable's type is
# (bash 5.2.37, the SQLite shell, Lua), from sources checked against their
# SHA-256; and with --eval, scores the decompiler's types against each.
#
# Usage: scripts/ground-truth.sh [--eval BINBUN] [dir]
#   --eval BINBUN  run `BINBUN eval types --totals` on each program built
#   dir            where sources and programs go
#                  (default ~/.cache/binbun-ground-truth)
# Needs: curl, sha256sum, tar, unzip, gcc, make.
#
# The programs are in dir/bin. `BINBUN eval types dir/bin/bash` gives the
# full report (the worst functions, split and merged structs).
set -euo pipefail

binbun=""
if [[ "${1:-}" == --eval ]]; then
    binbun="$(command -v "${2:?--eval needs the binbun binary}")"
    binbun="$(realpath "$binbun")"
    shift 2
fi
dest="${1:-$HOME/.cache/binbun-ground-truth}"
mkdir -p "$dest/src" "$dest/bin"
jobs="$(nproc)"

# name, URL, SHA-256
sources=(
    "bash.tar.gz https://ftp.gnu.org/gnu/bash/bash-5.2.37.tar.gz 9599b22ecd1d5787ad7d3b7bf0c59f312b3396d1e281175dd1f8a4014da621ff"
    "sqlite.zip https://www.sqlite.org/2026/sqlite-amalgamation-3540100.zip 0a9c8e34352dad46006aa82836d5383bff9dc6bc9ce5a60553c05aa30e6ad1f9"
    "lua.tar.gz https://www.lua.org/ftp/lua-5.4.9.tar.gz 2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6"
)

for entry in "${sources[@]}"; do
    read -r name url sum <<<"$entry"
    archive="$dest/src/$name"
    if [[ ! -f "$archive" ]]; then
        curl -sSfL -o "$archive.part" "$url"
        mv "$archive.part" "$archive"
    fi
    echo "$sum  $archive" | sha256sum --check --quiet
done

cd "$dest/src"

# The sources predate C23, whose `()` means no parameters: gnu17.
if [[ ! -x "$dest/bin/bash" ]]; then
    rm -rf bash-5.2.37
    tar -xzf bash.tar.gz
    (
        cd bash-5.2.37
        CFLAGS="-O2 -g -std=gnu17" ./configure --without-bash-malloc >configure.log 2>&1
        make -j"$jobs" >make.log 2>&1
    )
    cp bash-5.2.37/bash "$dest/bin/bash"
fi

if [[ ! -x "$dest/bin/sqlite3" ]]; then
    rm -rf sqlite-amalgamation-3540100
    unzip -q sqlite.zip
    gcc -O2 -g -std=gnu17 -o "$dest/bin/sqlite3" \
        sqlite-amalgamation-3540100/shell.c sqlite-amalgamation-3540100/sqlite3.c -lm
fi

if [[ ! -x "$dest/bin/lua" ]]; then
    rm -rf lua-5.4.9
    tar -xzf lua.tar.gz
    make -C lua-5.4.9 -j"$jobs" linux MYCFLAGS="-g" >lua-make.log 2>&1
    cp lua-5.4.9/src/lua "$dest/bin/lua"
fi

if [[ -n "$binbun" ]]; then
    for program in bash sqlite3 lua; do
        echo "$program: $("$binbun" eval types "$dest/bin/$program" --totals)"
    done
fi
