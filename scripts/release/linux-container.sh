#!/bin/sh
# Runs a command in the release's Linux build environment, an AlmaLinux 8
# container (glibc 2.28) prepared by container-setup.sh, with this tree
# mounted at /binbun, for local builds identical to the release
# workflow's. Docker or Podman.
#
#   scripts/release/linux-container.sh [COMMAND...]
#
# The default command packs the app and the CLI for the host's
# architecture into target/dist:
#   BINBUN_MAX_GLIBC=2.28 scripts/release/package-linux.sh
# The build goes to target/container (CARGO_TARGET_DIR) and the toolchain
# and crate downloads to target/container-home, both under this tree, so
# the host's ~/.cargo and target/ are untouched; files are made as the
# calling user.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
# The same image, by digest, as the release workflow's Linux jobs.
image=${BINBUN_LINUX_IMAGE:-docker.io/library/almalinux:8@sha256:2d0f2eb2a83cc09dbc2eb92fade4dbe8f709628149e81aa00aec70630406603b}
engine=$(command -v docker || command -v podman) || {
    echo "linux-container.sh: needs docker or podman" >&2
    exit 1
}
[ $# -gt 0 ] || set -- env BINBUN_MAX_GLIBC=2.28 scripts/release/package-linux.sh
mkdir -p "$root/target/container" "$root/target/container-home"

# The tools are installed as root, then the command runs as the caller.
# shellcheck disable=SC2016 # expanded in the container
exec "$engine" run --rm -i \
    -v "$root:/binbun" -w /binbun \
    -e CARGO_HOME=/binbun/target/container-home/cargo \
    -e RUSTUP_HOME=/binbun/target/container-home/rustup \
    -e CARGO_TARGET_DIR=/binbun/target/container \
    -e CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-}" \
    -e SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-}" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    "$image" sh -euc '
        scripts/release/container-setup.sh
        chown -R "$HOST_UID:$HOST_GID" "$CARGO_HOME" "$RUSTUP_HOME"
        [ -n "$CARGO_BUILD_JOBS" ] || unset CARGO_BUILD_JOBS
        [ -n "$SOURCE_DATE_EPOCH" ] || unset SOURCE_DATE_EPOCH
        exec setpriv --reuid="$HOST_UID" --regid="$HOST_GID" --clear-groups \
            env HOME=/binbun/target/container-home PATH="$CARGO_HOME/bin:$PATH" "$@"
    ' sh "$@"
