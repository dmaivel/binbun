#!/bin/sh
# Completes a release's directory of files: SHA256SUMS over every file in
# it, then install.sh (make-install-sh.sh) and latest.json, the update
# feed binbun_cli::update reads (schema 1), and SHA256SUMS again with those two.
#
#   scripts/release/release-files.sh X.Y.Z DIR
#
# latest.json's date and its security flag (a "### Security" group) come
# from the version's CHANGELOG.md section; its notes link to the GitHub
# release, its download to the latest release's page.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
version=${1:?usage: $0 X.Y.Z DIR}
version=${version#v}
dir=${2:?usage: $0 X.Y.Z DIR}
repository=https://github.com/dmaivel/binbun

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

sums() {
    (cd "$dir" && find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' | sed 's|^\./||' | LC_ALL=C sort |
        while IFS= read -r name; do sha256 "$name"; done) >"$dir/SHA256SUMS.new"
    mv "$dir/SHA256SUMS.new" "$dir/SHA256SUMS"
}

rm -f "$dir/SHA256SUMS" "$dir/install.sh" "$dir/latest.json"
sums
"$here/make-install-sh.sh" "$version" "$dir/SHA256SUMS" >"$dir/install.sh"
chmod 755 "$dir/install.sh"

date=$("$here/changelog.sh" date "$version")
security=false
if "$here/changelog.sh" security "$version"; then security=true; fi
printf '{"schema":1,"version":"%s","date":"%s","notes":"%s","download":"%s","security":%s}\n' \
    "$version" "$date" "$repository/releases/tag/v$version" "$repository/releases/latest" "$security" \
    >"$dir/latest.json"
sums
cat "$dir/SHA256SUMS"
