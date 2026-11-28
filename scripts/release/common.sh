# Sourced by the packaging scripts in scripts/release (bash 3.2 and up:
# macOS's /bin/bash, Git Bash on Windows): the tree's root, the release
# version, the target, reproducible-build settings and archive helpers.
# shellcheck shell=bash

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

die() {
    echo "${0##*/}: $*" >&2
    exit 1
}

# The version of [workspace.package] in the Cargo.toml given (default the
# root workspace's): the version of every artifact (one version for all).
workspace_version() {
    awk '
        /^\[workspace\.package\]/ { section = 1; next }
        /^\[/ { section = 0 }
        section && /^version *=/ { sub(/^version *= *"/, ""); sub(/".*/, ""); print; exit }
    ' "${1:-$root/Cargo.toml}"
}

# The version, checked to be the same in both workspaces.
release_version() {
    local engine gui
    engine=$(workspace_version "$root/Cargo.toml")
    gui=$(workspace_version "$root/gui/Cargo.toml")
    [ -n "$engine" ] || die "no [workspace.package] version in Cargo.toml"
    [ "$engine" = "$gui" ] || die "Cargo.toml says $engine, gui/Cargo.toml says $gui: one version for everything"
    echo "$engine"
}

# The host's target triple, as the pinned toolchain sees it.
host_target() {
    (cd "$root" && rustc -vV) | sed -n 's/^host: //p'
}

# The pinned toolchain's standard library for target $1, added with
# rustup if missing.
ensure_target() {
    (cd "$root" && { rustup target list --installed | grep -qx "$1" || rustup target add "$1"; })
}

# A path as the compiler sees it (Windows paths under Git Bash).
native_path() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -w "$1"; else echo "$1"; fi
}

# Settings that make a build independent of where it ran: no home or
# checkout paths in the binaries (rustc's --remap-path-prefix, the C
# compiler's -ffile-prefix-map for build scripts' C), symbols stripped,
# and SOURCE_DATE_EPOCH (the commit's time) for archive timestamps.
reproducible_env() {
    if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
        # Outside a git checkout: a fixed time (1980-01-01, zip's first).
        SOURCE_DATE_EPOCH=$(git -C "$root" log -1 --format=%ct 2>/dev/null || echo 315532800)
    fi
    export SOURCE_DATE_EPOCH
    local sysroot cargo_home tree
    sysroot=$(native_path "$(cd "$root" && rustc --print sysroot)")
    cargo_home=$(native_path "${CARGO_HOME:-$HOME/.cargo}")
    tree=$(native_path "$root")
    # rustc applies the last prefix that matches: the broadest first (the
    # cargo home or the target directory may be inside the tree).
    RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$tree=/binbun --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$sysroot=/rustc"
    if [ -n "${CARGO_TARGET_DIR:-}" ]; then
        # Build scripts' outputs (OUT_DIR) included by path.
        RUSTFLAGS="$RUSTFLAGS --remap-path-prefix=$(native_path "$CARGO_TARGET_DIR")=/target"
    fi
    export RUSTFLAGS
    case $(uname -s) in
        MINGW* | MSYS* | CYGWIN*) ;; # MSVC's cl takes no -ffile-prefix-map
        # Here too the last map that matches applies.
        *) export CFLAGS="${CFLAGS:+$CFLAGS }-ffile-prefix-map=$tree=/binbun -ffile-prefix-map=$cargo_home=/cargo" ;;
    esac
    export CARGO_PROFILE_RELEASE_STRIP=symbols
    export CARGO_PROFILE_RELEASE_DEBUG=0
}

# Licence and notice files every archive carries, copied into $1; the
# rest (app, cli, capi) name the third_party/licenses/ files listing the
# licences of the crates its executables are built from
# (third-party-licenses.sh): one is licenses/THIRD-PARTY-LICENSES.md,
# several are licenses/THIRD-PARTY-LICENSES-<kind>.md.
copy_notices() {
    local dir=$1 kind
    shift
    [ $# -gt 0 ] || die "copy_notices: which licence lists?"
    mkdir -p "$dir/licenses"
    cp "$root/README.md" "$root/CHANGELOG.md" "$root/LICENSE-MIT" "$root/LICENSE-APACHE" "$dir/"
    cp "$root/third_party/xed/LICENSE" "$dir/licenses/LICENSE-XED"
    cp "$root/third_party/aarchmrs/notice.html" "$dir/licenses/NOTICE-AARCHMRS.html"
    for kind in "$@"; do
        [ -f "$root/third_party/licenses/$kind.md" ] || die "no third_party/licenses/$kind.md"
        if [ $# -eq 1 ]; then
            cp "$root/third_party/licenses/$kind.md" "$dir/licenses/THIRD-PARTY-LICENSES.md"
        else
            cp "$root/third_party/licenses/$kind.md" "$dir/licenses/THIRD-PARTY-LICENSES-$kind.md"
        fi
    done
    chmod 644 "$dir"/*.md "$dir"/LICENSE-* "$dir"/licenses/*
}

# The licences of what the GUI embeds, copied into $1/licenses: its fonts',
# its bundled themes' (gui/THEMES and each upstream's text) and its
# terminal emulator's (gui/LIBGHOSTTY and the texts of what it links).
copy_gui_notices() {
    mkdir -p "$1/licenses/themes" "$1/licenses/libghostty"
    cp "$root"/gui/app/assets/fonts/OFL-*.txt "$1/licenses/"
    cp "$root/gui/THEMES" "$1/licenses/THEMES.txt"
    cp "$root"/third_party/themes/*.txt "$1/licenses/themes/"
    cp "$root/gui/LIBGHOSTTY" "$1/licenses/LIBGHOSTTY.txt"
    cp "$root"/third_party/libghostty/*.txt "$1/licenses/libghostty/"
    chmod 644 "$1"/licenses/OFL-*.txt "$1/licenses/THEMES.txt" "$1"/licenses/themes/*.txt \
        "$1/licenses/LIBGHOSTTY.txt" "$1"/licenses/libghostty/*.txt
}

# Files' modification times set to SOURCE_DATE_EPOCH, under directory $1.
touch_tree() {
    local stamp
    stamp=$(date -u -d "@$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S 2>/dev/null ||
        date -u -r "$SOURCE_DATE_EPOCH" +%Y%m%d%H%M.%S)
    find "$1" -exec touch -h -t "$stamp" {} + 2>/dev/null || find "$1" -exec touch -t "$stamp" {} +
}

# The signature packs (`*.jsonl.zst`: scripts/signatures/packs.sh's, and
# those made by hand it adds with --hand-built) of
# directory $1 copied into $2, where binbun reads packs installed with it
# (binbun_session::signatures::folders); fails if $1 holds none.
copy_signatures() {
    local from=$1 to=$2 pack found=
    mkdir -p "$to"
    for pack in "$from"/*.jsonl.zst; do
        [ -f "$pack" ] || continue
        install -m 644 "$pack" "$to/"
        found=1
    done
    [ -n "$found" ] || die "$from holds no signature pack (*.jsonl.zst)"
}

# A gzipped tar of directory $2/$3 into $1, the same bytes for the same
# files: names sorted, owner 0, times SOURCE_DATE_EPOCH, no gzip time.
# GNU tar sorts; bsdtar (macOS) adds the names in directory order.
tar_gz() {
    local out=$1 base=$2 name=$3 tar=tar
    command -v gtar >/dev/null 2>&1 && tar=gtar
    touch_tree "$base/$name"
    if "$tar" --version 2>/dev/null | grep -q 'GNU tar'; then
        "$tar" --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
            --format=gnu -C "$base" -cf - "$name" | gzip -9n >"$out"
    else
        "$tar" --uid 0 --gid 0 --uname '' --gname '' -C "$base" -cf - "$name" | gzip -9n >"$out"
    fi
}

# A zip of the contents of directory $2 into $1 (7-Zip on Windows, else
# zip), times SOURCE_DATE_EPOCH.
zip_dir() {
    local out=$1 dir=$2
    touch_tree "$dir"
    rm -f "$out"
    if command -v 7z >/dev/null 2>&1; then
        (cd "$dir" && 7z a -tzip -mx=9 -bd -bso0 "$(native_path "$out")" .)
    else
        (cd "$dir" && find . -type f | LC_ALL=C sort | zip -X -9 -q "$out" -@)
    fi
}

# Directory $1, made if missing, as an absolute path.
absolute_dir() {
    mkdir -p "$1" && (cd "$1" && pwd)
}
