#!/usr/bin/env bash
# Runs the pinned Zig (scripts/zig.sh), fetching it into gui/target/zig the
# first time: the ZIG of the GUI's cargo builds (gui/.cargo/config.toml), so
# that libghostty-vt's source build finds it with nothing installed. Not on
# Windows, which runs no shell script as a program: set ZIG to zig.sh's
# output there.
set -euo pipefail
zig=$("$(dirname "$0")/zig.sh")
exec "$zig" "$@"
