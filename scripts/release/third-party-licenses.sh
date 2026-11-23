#!/usr/bin/env bash
# The licences of the crates each download is built from, written by
# cargo-about (about.toml, third_party/licenses/template.md.hbs) to
# third_party/licenses/: app.md (the app, binbun-gui), cli.md (the
# command-line-only builds, binbun-cli), capi.md (libbinbun) and
# python.md (the wheel, binbun-py). Every target's dependencies are in
# each, build and dev dependencies left out. The packaging scripts copy
# them into the downloads (common.sh, copy_notices) and the wheel lists
# python.md among its licence files; the release refuses files that are
# not current. Run it after Cargo.lock or gui/Cargo.lock changes.
#
#   scripts/release/third-party-licenses.sh           write them
#   scripts/release/third-party-licenses.sh --check   write nothing; fail if one is not current
#
# Needs cargo-about 0.9.3 (install-cargo-about.sh) and the network once
# (cargo fetch); the files are made offline from the locked versions.
set -euo pipefail
# shellcheck source-path=SCRIPTDIR source=common.sh
. "$(dirname "$0")/common.sh"

check=
case ${1:-} in
    --check) check=1 ;;
    "") ;;
    *) die "usage: $0 [--check]" ;;
esac
version=0.9.3
command -v cargo-about >/dev/null || die "cargo-about is not installed (scripts/release/install-cargo-about.sh)"
installed=$(cargo-about --version | awk '{ print $2 }')
[ "$installed" = "$version" ] || die "cargo-about is $installed, the files are made by $version"

cd "$root"
(cargo fetch --locked >/dev/null && cd gui && cargo fetch --locked >/dev/null) ||
    die "cannot fetch the locked crates"

out=$root/third_party/licenses
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
stale=
for pair in app:gui/app cli:crates/binbun-cli capi:crates/binbun-capi python:crates/binbun-py; do
    name=${pair%%:*} crate=${pair#*:}
    cargo about generate --frozen --fail -c about.toml -m "$crate/Cargo.toml" \
        third_party/licenses/template.md.hbs -o "$work/$name.md" 2>"$work/$name.log" || {
        cat "$work/$name.log" >&2
        die "cargo-about failed for $crate"
    }
    if [ -n "$check" ]; then
        cmp -s "$work/$name.md" "$out/$name.md" || {
            echo "third-party-licenses.sh: third_party/licenses/$name.md is not current" >&2
            stale=1
        }
    else
        cp "$work/$name.md" "$out/$name.md"
    fi
done
[ -z "$stale" ] || die "run scripts/release/third-party-licenses.sh and commit the files"
