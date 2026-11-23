#!/bin/sh
# The GitHub release's notes for X.Y.Z: its CHANGELOG.md section, how to
# install, a table of the downloads in DIR, and how to verify them. Each
# paragraph is one line: GitHub wraps them.
#
#   scripts/release/release-notes.sh X.Y.Z DIR
#
# DIR holds the release's files (the release workflow's dist/); a file
# the table cannot describe stops the script, so none is left out.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
version=${1:?usage: $0 X.Y.Z DIR}
version=${version#v}
dir=${2:?usage: $0 X.Y.Z DIR}
download=https://github.com/dmaivel/binbun/releases/download/v$version

# The platform a file's target triple names.
platform() {
    case $1 in
        *aarch64-apple-darwin*) echo "Apple Silicon macOS" ;;
        *x86_64-apple-darwin*) echo "Intel macOS" ;;
        *aarch64-unknown-linux-gnu*) echo "ARM64 Linux" ;;
        *x86_64-unknown-linux-gnu*) echo "x64 Linux" ;;
        *aarch64-unknown-linux-musl*) echo "ARM64 Linux, static (musl)" ;;
        *x86_64-unknown-linux-musl*) echo "x64 Linux, static (musl)" ;;
        *aarch64-pc-windows-msvc*) echo "ARM64 Windows" ;;
        *x86_64-pc-windows-msvc*) echo "x64 Windows" ;;
        *) return 1 ;;
    esac
}

# What a file holds.
contents() {
    case $1 in
        libbinbun-*) echo "C library (the decoders, so far), headers and pkg-config file" ;;
        binbun-cli-*) echo "Command line alone, for servers and containers" ;;
        binbun-*-linux-gnu.tar.gz) echo "App and command (glibc 2.28 or later)" ;;
        binbun-*.dmg) echo "App and command" ;;
        # printf: dash's echo, Ubuntu's sh, reads \b as a backspace.
        binbun-*-windows-msvc.zip) printf '%s\n' "App (\`binbun.exe\`) and command (\`bin\\binbun.exe\`)" ;;
        *) return 1 ;;
    esac
}

"$here/changelog.sh" notes "$version"
cat <<EOF

## Install binbun $version

### Linux and macOS

\`\`\`sh
curl -fsSL https://binbun.org/install.sh | sh
\`\`\`

Installs the app and the command into your home directory, no root needed; every download is checked against the SHA-256 written into the script (\`install.sh\`, attached below). \`--cli\` installs the command line alone, \`--uninstall\` removes binbun, and \`--help\` lists the rest.

### Python

\`\`\`sh
pip install binbun==$version
\`\`\`

CPython 3.11 or later.

## Download binbun $version

| File | Platform | Contents |
|------|----------|----------|
EOF
found=
for path in "$dir"/*; do
    name=$(basename "$path")
    case $name in
        SHA256SUMS | install.sh | latest.json) continue ;;
    esac
    where=$(platform "$name") || { echo "release-notes.sh: no platform for $name" >&2; exit 1; }
    what=$(contents "$name") || { echo "release-notes.sh: nothing said of $name" >&2; exit 1; }
    echo "| [$name]($download/$name) | $where | $what |"
    found=1
done
[ -n "$found" ] || { echo "release-notes.sh: $dir holds no downloads" >&2; exit 1; }
cat <<EOF

- **macOS:** the app is not signed with an Apple Developer ID yet. After its first launch is refused, allow it in System Settings → Privacy & Security → Open Anyway. The copy \`install.sh\` installs needs no such step.
- **Windows:** unzip it anywhere, and add its \`bin\` folder to PATH to type \`binbun\` in a shell. It is not signed yet: at the first run, SmartScreen's "Windows protected your PC" needs More info → Run anyway.

## Verify

\`sha256sum -c SHA256SUMS --ignore-missing\` checks the files you downloaded. Each file was built and attested by this repository's release workflow: \`gh attestation verify FILE --repo dmaivel/binbun\`.
EOF
