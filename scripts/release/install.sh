#!/bin/sh
# Installs binbun @VERSION@ for the current user: no root, nothing outside
# the prefix (default ~/.local) and, on macOS, ~/Applications.
#
#   curl -fsSL https://binbun.org/install.sh | sh
#   curl -fsSL https://binbun.org/install.sh | sh -s -- [OPTIONS]
#
#   --cli                 Linux: the command line alone (no GUI); chosen
#                         anyway on musl, on glibc older than 2.28, and
#                         where the GUI's libraries (libxcb,
#                         libxkbcommon, libxkbcommon-x11) are missing
#   --prefix DIR          install under DIR (default ~/.local): the
#                         command in DIR/bin, the files in DIR/lib/binbun
#   --from DIR            take the release files from DIR instead of
#                         downloading them (still checked)
#   --verify-attestation  also check GitHub's build attestation of the
#                         download (needs the gh command, signed in)
#   --uninstall           remove what this script installed
#
# Every file is checked against the SHA-256 written into this script when
# release @VERSION@ was made (scripts/release/make-install-sh.sh) before
# anything is unpacked; a mismatch stops the install. Other versions'
# scripts are at https://binbun.org/install/X.Y.Z.sh and attached to each
# release on GitHub. The whole script is one function called on its last
# line, so a download cut short runs nothing.
#
# Linux: the app (binbun.app from the release's tar.gz) goes in
# DIR/lib/binbun/@VERSION@, with `binbun` linked in DIR/bin and a desktop
# entry and icons in DIR/share. macOS: binbun.app is copied from the dmg
# into ~/Applications and `binbun` linked in DIR/bin. Windows: use the
# zip from the release page, or winget.

VERSION='@VERSION@'
REPOSITORY='dmaivel/binbun'

# The SHA-256 of each release file this script may install.
sha256_of() {
    case $1 in
        # @CHECKSUMS@
        *) return 1 ;;
    esac
}

say() {
    printf 'binbun-install: %s\n' "$*"
}

die() {
    printf 'binbun-install: %s\n' "$*" >&2
    exit 1
}

usage() {
    sed -n '/^#   --cli/,/^#   --uninstall/s/^# \{0,1\}//p' "$0" 2>/dev/null ||
        echo "options: --cli --prefix DIR --from DIR --verify-attestation --uninstall"
}

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | cut -d ' ' -f 1
    elif command -v openssl >/dev/null 2>&1; then
        openssl dgst -sha256 -r "$1" | cut -d ' ' -f 1
    else
        die "needs sha256sum, shasum or openssl to check the download"
    fi
}

# The release file $1 into $2, from --from's directory or GitHub, checked.
fetch() {
    expected=$(sha256_of "$1") || die "no checksum for $1 in this script (release $VERSION has no such file)"
    if [ -n "$from" ]; then
        [ -f "$from/$1" ] || die "$from/$1: no such file"
        cp "$from/$1" "$2"
    else
        url="https://github.com/$REPOSITORY/releases/download/v$VERSION/$1"
        say "downloading $url"
        if command -v curl >/dev/null 2>&1; then
            curl --proto '=https' --tlsv1.2 -fL --retry 3 --progress-bar -o "$2" "$url" ||
                die "download failed: $url"
        elif command -v wget >/dev/null 2>&1; then
            wget --https-only -q -O "$2" "$url" || die "download failed: $url"
        else
            die "needs curl or wget"
        fi
    fi
    actual=$(sha256 "$2")
    [ "$actual" = "$expected" ] ||
        die "$1: SHA-256 is $actual, expected $expected; nothing was installed"
    say "$1: SHA-256 checked"
    if [ -n "$verify_attestation" ]; then
        command -v gh >/dev/null 2>&1 || die "--verify-attestation needs the gh command"
        gh attestation verify "$2" --repo "$REPOSITORY" >/dev/null ||
            die "$1: GitHub's attestation does not verify; nothing was installed"
        say "$1: attestation verified"
    fi
}

# Whether the shared library $1 can be found by the dynamic loader.
has_library() {
    for ldconfig in ldconfig /sbin/ldconfig /usr/sbin/ldconfig; do
        if command -v "$ldconfig" >/dev/null 2>&1; then
            "$ldconfig" -p 2>/dev/null | grep -q "^[[:space:]]*$1 " && return 0
            break
        fi
    done
    for dir in /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib "/usr/lib/$arch-linux-gnu" "/lib/$arch-linux-gnu"; do
        [ -e "$dir/$1" ] && return 0
    done
    return 1
}

# Records path $1 as installed (removed by --uninstall).
installed() {
    printf '%s\n' "$1" >>"$libdir/INSTALLED.new"
}

finish_record() {
    mv "$libdir/INSTALLED.new" "$libdir/INSTALLED"
}

link_command() {
    mkdir -p "$bindir"
    ln -sfn "$1" "$bindir/binbun"
    installed "$bindir/binbun"
}

install_linux() {
    libc=gnu
    if [ -e "/lib/ld-musl-$arch.so.1" ] || ldd --version 2>&1 | grep -qi musl; then
        libc=musl
    fi
    kind=app
    if [ -n "$cli" ]; then
        kind=cli
    elif [ "$libc" = musl ]; then
        kind=cli
        say "musl libc: installing the command line alone (the app needs glibc)"
    else
        glibc=$(getconf GNU_LIBC_VERSION 2>/dev/null | sed 's/^glibc //')
        major=${glibc%%.*} minor=${glibc#*.}
        minor=${minor%%.*}
        if [ -n "$glibc" ] && { [ "$major" -lt 2 ] || { [ "$major" -eq 2 ] && [ "$minor" -lt 28 ]; }; }; then
            libc=musl kind=cli
            say "glibc $glibc is older than 2.28: installing the static command line alone"
        else
            missing=
            for library in libxcb.so.1 libxkbcommon.so.0 libxkbcommon-x11.so.0; do
                has_library "$library" || missing="$missing $library"
            done
            if [ -n "$missing" ]; then
                kind=cli
                say "no$missing here: installing the command line alone (install them and run this again for the app)"
            fi
        fi
    fi

    if [ "$kind" = app ]; then
        asset=binbun-$VERSION-$arch-unknown-linux-gnu.tar.gz
    else
        asset=binbun-cli-$VERSION-$arch-unknown-linux-$libc.tar.gz
    fi
    fetch "$asset" "$work/$asset"

    mkdir -p "$libdir"
    : >"$libdir/INSTALLED.new"
    rm -rf "$libdir/$VERSION.new"
    mkdir -p "$libdir/$VERSION.new"
    tar -xzf "$work/$asset" -C "$libdir/$VERSION.new" --strip-components=1 ||
        die "could not unpack $asset"
    rm -rf "${libdir:?}/$VERSION"
    mv "$libdir/$VERSION.new" "$libdir/$VERSION"
    installed "$libdir/$VERSION"
    link_command "$libdir/$VERSION/bin/binbun"

    if [ "$kind" = app ]; then
        share=$prefix/share
        mkdir -p "$share/applications"
        # The installed command's path, so the launcher works whatever PATH
        # the desktop session has.
        sed "s|^Exec=[^ ]*|Exec=$bindir/binbun|" \
            "$libdir/$VERSION/share/applications/binbun.desktop" >"$share/applications/binbun.desktop"
        installed "$share/applications/binbun.desktop"
        for icon in "$libdir/$VERSION"/share/icons/hicolor/*/apps/binbun.*; do
            size=$(basename "$(dirname "$(dirname "$icon")")")
            mkdir -p "$share/icons/hicolor/$size/apps"
            cp "$icon" "$share/icons/hicolor/$size/apps/"
            installed "$share/icons/hicolor/$size/apps/$(basename "$icon")"
        done
        command -v update-desktop-database >/dev/null 2>&1 &&
            update-desktop-database -q "$share/applications" 2>/dev/null || true
        if missing=$(ldd "$libdir/$VERSION/bin/binbun" 2>/dev/null | grep 'not found'); then
            say "warning: libraries binbun needs were not found:"
            printf '%s\n' "$missing" >&2
        fi
    fi
    remove_other_versions
    finish_record
}

install_macos() {
    [ -z "$cli" ] || die "--cli is for Linux: on macOS the app is the command"
    asset=binbun-$VERSION-$arch-apple-darwin.dmg
    fetch "$asset" "$work/$asset"
    mkdir -p "$libdir" "$work/mount"
    : >"$libdir/INSTALLED.new"
    hdiutil attach -quiet -nobrowse -readonly -noautoopen -mountpoint "$work/mount" "$work/$asset" ||
        die "could not open $asset"
    applications=$HOME/Applications
    mkdir -p "$applications"
    rm -rf "$applications/binbun.app.new"
    ditto "$work/mount/binbun.app" "$applications/binbun.app.new" || {
        hdiutil detach -quiet "$work/mount"
        die "could not copy binbun.app"
    }
    hdiutil detach -quiet "$work/mount" || true
    rm -rf "$applications/binbun.app"
    mv "$applications/binbun.app.new" "$applications/binbun.app"
    installed "$applications/binbun.app"
    link_command "$applications/binbun.app/Contents/MacOS/binbun"
    remove_other_versions
    finish_record
}

# Earlier versions this script unpacked under $libdir.
remove_other_versions() {
    for dir in "$libdir"/*; do
        [ -d "$dir" ] || continue
        [ "$dir" = "$libdir/$VERSION" ] || rm -rf "$dir"
    done
}

uninstall() {
    [ -f "$libdir/INSTALLED" ] || die "nothing to remove: no $libdir/INSTALLED"
    while IFS= read -r path; do
        case $path in
            "$prefix"/* | "$HOME/Applications/binbun.app")
                if [ -e "$path" ] || [ -L "$path" ]; then
                    rm -rf "$path"
                    say "removed $path"
                fi
                ;;
            *) say "kept $path (outside $prefix)" ;;
        esac
    done <"$libdir/INSTALLED"
    rm -rf "$libdir"
    say "binbun is uninstalled"
}

main() {
    set -eu
    case $VERSION in
        @*) die "this is install.sh's template; scripts/release/make-install-sh.sh makes a release's script" ;;
    esac

    cli='' from='' prefix='' verify_attestation='' action=install
    while [ $# -gt 0 ]; do
        case $1 in
            --cli) cli=1 ;;
            --prefix) [ $# -ge 2 ] || die "--prefix needs a directory"; prefix=$2; shift ;;
            --prefix=*) prefix=${1#--prefix=} ;;
            --from) [ $# -ge 2 ] || die "--from needs a directory"; from=$2; shift ;;
            --from=*) from=${1#--from=} ;;
            --verify-attestation) verify_attestation=1 ;;
            --uninstall) action=uninstall ;;
            -h | --help) usage; exit 0 ;;
            *) die "unknown option $1 (--help lists them)" ;;
        esac
        shift
    done
    [ -n "${HOME:-}" ] || die "HOME is not set"
    prefix=${prefix:-$HOME/.local}
    case $prefix in /*) ;; *) prefix=$(pwd)/$prefix ;; esac
    if [ -n "$from" ]; then
        case $from in /*) ;; *) from=$(pwd)/$from ;; esac
    fi
    bindir=$prefix/bin
    libdir=$prefix/lib/binbun

    if [ "$action" = uninstall ]; then
        uninstall
        return
    fi

    case $(uname -m) in
        x86_64 | amd64) arch=x86_64 ;;
        aarch64 | arm64) arch=aarch64 ;;
        *) die "no binbun build for $(uname -m)" ;;
    esac
    work=$(mktemp -d "${TMPDIR:-/tmp}/binbun-install.XXXXXX")
    trap 'rm -rf "$work"' EXIT
    trap 'exit 1' HUP INT TERM

    case $(uname -s) in
        Linux) install_linux ;;
        Darwin) install_macos ;;
        *) die "this script installs on Linux and macOS; on Windows use the zip from https://github.com/$REPOSITORY/releases or winget" ;;
    esac

    say "installed binbun $VERSION: $bindir/binbun"
    case ":${PATH:-}:" in
        *":$bindir:"*) ;;
        *)
            say "$bindir is not on your PATH; add it in your shell's startup file:"
            # shellcheck disable=SC2016 # the line to paste, $PATH unexpanded
            printf '    export PATH="%s:$PATH"\n' "$bindir"
            ;;
    esac
}

main "$@"
