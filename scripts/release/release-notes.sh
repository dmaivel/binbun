#!/bin/sh
# The GitHub release's notes for X.Y.Z: its CHANGELOG.md section, then
# how to install and verify the files.
#
#   scripts/release/release-notes.sh X.Y.Z
set -eu

here=$(cd "$(dirname "$0")" && pwd)
version=${1:?usage: $0 X.Y.Z}
version=${version#v}

"$here/changelog.sh" notes "$version"
cat <<EOF

## Install

- **Linux and macOS**: \`curl -fsSL https://binbun.org/install.sh | sh\`
  installs into your home directory (no root); every download is checked
  against the SHA-256 written into the script, which is attached below
  (\`install.sh\`). Run it with \`--help\` for its options (\`--cli\` for the
  command line alone, \`--uninstall\`).
- **Linux by hand**: \`binbun-$version-<arch>-unknown-linux-gnu.tar.gz\` is
  the app (glibc 2.28 or later); \`binbun-cli-$version-…\` is the command
  line alone, for servers and containers (\`-musl\`: static).
- **macOS**: \`binbun-$version-<arch>-apple-darwin.dmg\`. The app is not
  signed with an Apple Developer ID yet: after the first launch is
  refused, allow it in System Settings → Privacy & Security → Open
  Anyway. install.sh's copy needs no such step.
- **Windows**: \`binbun-$version-<arch>-pc-windows-msvc.zip\` holds
  the app, \`binbun.exe\`, and the command, \`bin\\binbun.exe\` (add that
  folder to PATH to type \`binbun\` in a shell); unzip it anywhere. It is
  not signed yet: at the first run, SmartScreen's "Windows protected your
  PC" needs More info → Run anyway.
- **Python**: \`pip install binbun==$version\` (CPython 3.11 or later).
- **C and C++**: \`libbinbun-$version-<target>\` holds binbun's C library
  (the decoders, so far), its headers and pkg-config file.

## Verify

\`sha256sum -c SHA256SUMS --ignore-missing\` checks the files you
downloaded. Each file was built and attested by this repository's release
workflow: \`gh attestation verify FILE --repo dmaivel/binbun\`.
EOF
