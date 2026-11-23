#!/bin/sh
# Prepares the Arch Linux container the Linux test jobs run in, so that
# the system files the tests read (/usr/bin/bash, /usr/lib/libc.so.6,
# libstdc++) are fixed inputs: the image is pinned by digest in the
# workflows and the packages come from the Arch Linux Archive's snapshot
# of one day, moved forward deliberately (with the answers that change).
#
#   scripts/ci/arch-setup.sh
#
# Installs the tools the tests use when present (z3, gcc and clang,
# llvm-dwarfdump, python) and rustup, whose toolchain is the one
# rust-toolchain.toml pins; the snapshot's LLVM (22) is the one the
# AArch64 oracle (scripts/llvm-oracle.sh) needs. Run as root in the
# container. The archive is one server, at times very slow: pacman waits
# for it rather than giving up after 10 s, and each step is tried three
# times; the workflows keep the packages (/var/cache/pacman/pkg) in
# GitHub's cache, keyed by this file, so they are fetched once a snapshot.
set -eu

# `pacman ARGS…`, tried up to three times.
pacman_retried() {
    for attempt in 1 2 3; do
        pacman --noconfirm --noprogressbar --disable-download-timeout "$@" && return 0
        [ "$attempt" = 3 ] && return 1
        echo "arch-setup.sh: pacman $* failed (attempt $attempt); again in 30 s" >&2
        sleep 30
    done
}

# glibc 2.44+r24, bash 5.3.20, gcc 16.2.1, LLVM 22.1.8, z3 4.16.0: the
# packages of the machine the tests' expectations were taken on.
snapshot=2026/09/25
echo "Server = https://archive.archlinux.org/repos/$snapshot/\$repo/os/\$arch" >/etc/pacman.d/mirrorlist
pacman_retried -Syyuu
pacman_retried -S --needed git rustup clang llvm z3 python python-pip
rustup set profile minimal
