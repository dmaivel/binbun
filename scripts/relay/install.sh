#!/usr/bin/env bash
# Installs relay.binbun.org's iroh-relay on HOST over SSH: copies this
# directory's setup.sh, config.toml, iroh-relay.service and
# journald@iroh-relay.conf there and runs setup.sh with sudo (see
# README.md). Safe to run again: it changes only what differs.
#
#   RELAY_EMAIL=you@example.org scripts/relay/install.sh HOST
#
# HOST: what ssh takes (`ubuntu@203.0.113.7`, or a name in ~/.ssh/config);
# a bare address or name logs in as ubuntu. RELAY_EMAIL: Let's Encrypt's
# contact, unless config.toml has one written in. RELAY_SSH: the ssh
# command with any options (default `ssh`).
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
root=$(cd "$here/../.." && pwd)

die() {
    echo "${0##*/}: $*" >&2
    exit 1
}

[ $# -eq 1 ] || die "usage: RELAY_EMAIL=ADDRESS ${0##*/} HOST"
host=$1
case $host in
    *@*) ;;
    *) host=ubuntu@$host ;;
esac
read -ra ssh <<<"${RELAY_SSH:-ssh}"
email=${RELAY_EMAIL:-}

# The relay pinned is the release of the iroh binbun is built with.
pinned=$(sed -n 's/^version=//p' "$here/setup.sh")
locked=$(awk '/^name = "iroh-relay"$/ { getline; gsub(/version = |"/, ""); print; exit }' "$root/Cargo.lock")
[ "$pinned" = "$locked" ] ||
    die "setup.sh pins iroh-relay $pinned, Cargo.lock has $locked: update version= and both SHA-256s in setup.sh"

if grep -q '@RELAY_EMAIL@' "$here/config.toml"; then
    [[ $email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] ||
        die "set RELAY_EMAIL to Let's Encrypt's contact address (or write it in config.toml)"
fi

echo "installing iroh-relay $pinned on $host"
# shellcheck disable=SC2016 # expanded on HOST
remote='set -e; dir=$(mktemp -d); trap "rm -rf \"$dir\"" EXIT; tar -xf - -C "$dir"; sudo -n bash "$dir/setup.sh" '
tar -C "$here" -cf - setup.sh config.toml iroh-relay.service journald@iroh-relay.conf |
    "${ssh[@]}" "$host" "$remote$(printf '%q' "$email")"
echo "installed; check it: scripts/relay/check.sh --ssh $host relay.binbun.org (--ip ADDRESS before DNS has it)"
