#!/usr/bin/env bash
# Run by install.sh on the relay's machine (Ubuntu 24.04), as root, from a
# directory holding config.toml, iroh-relay.service and
# journald@iroh-relay.conf: installs iroh-relay (the release binary,
# checksum pinned) as a hardened systemd service under its own user,
# opens its ports and starts it. Running it again changes only what
# differs, and restarts the relay only then.
#
#   setup.sh [EMAIL]    EMAIL fills config.toml's @RELAY_EMAIL@
set -euo pipefail

# iroh-relay's release matching binbun's iroh (Cargo.lock; install.sh
# checks), and the SHA-256 of each archive (GitHub's release digests,
# checked against the downloads).
version=1.4.1
sha256_aarch64=3fc0c2d67c1cd66250bf82f3e2f17a985b7081a3d272186bad9d63e3f2347b38
sha256_x86_64=75254641e3fad7fcbac6dee4d485556fbe06ef708340a9d8810469270ba626b8

# The relay's ports: HTTP (captive-portal probe), HTTPS (the relay, and
# Let's Encrypt's TLS-ALPN-01), and QUIC address discovery.
tcp_ports=(80 443)
udp_ports=(7842)

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
email=${1:-}

die() {
    echo "setup.sh: $*" >&2
    exit 1
}
say() { echo "== $*"; }

[ "$(id -u)" = 0 ] || die "run as root"

case $(uname -m) in
    aarch64) target=aarch64-unknown-linux-musl sha256=$sha256_aarch64 ;;
    x86_64) target=x86_64-unknown-linux-musl sha256=$sha256_x86_64 ;;
    *) die "no iroh-relay pinned for $(uname -m)" ;;
esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Whether anything the running relay reads changed.
changed=0

# Installs SOURCE as DEST (mode MODE, group GROUP) if it differs.
put() {
    local source=$1 dest=$2 mode=$3 group=$4
    if ! cmp -s "$source" "$dest"; then
        install -m "$mode" -o root -g "$group" "$source" "$dest"
        say "installed $dest"
        changed=1
    fi
}

ufw_active() {
    command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'
}

# Packages: curl to download; iptables-persistent keeps the rules over
# reboots (Oracle's images have it; Oracle says not to use ufw on them).
packages=(curl ca-certificates)
ufw_active || packages+=(iptables iptables-persistent)
missing=()
for package in "${packages[@]}"; do
    dpkg-query -W -f '${Status}' "$package" 2>/dev/null | grep -q 'ok installed' ||
        missing+=("$package")
done
if [ ${#missing[@]} -gt 0 ]; then
    say "installing ${missing[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q --no-install-recommends "${missing[@]}"
fi

# The binary.
binary=/usr/local/bin/iroh-relay
if [ "$("$binary" --version 2>/dev/null || true)" != "iroh-relay $version" ]; then
    archive=iroh-relay-v$version-$target.tar.gz
    say "downloading $archive"
    curl -fsSL --proto '=https' --tlsv1.2 -o "$work/$archive" \
        "https://github.com/n0-computer/iroh/releases/download/v$version/$archive"
    echo "$sha256  $work/$archive" | sha256sum -c --quiet - ||
        die "$archive: not the SHA-256 pinned"
    tar -xzf "$work/$archive" -C "$work" --no-same-owner ./iroh-relay
    install -m 0755 -o root -g root "$work/iroh-relay" "$binary.new"
    mv -f "$binary.new" "$binary"
    say "installed $("$binary" --version)"
    changed=1
fi

# Its user: no login, no home but the state directory systemd makes.
if ! getent passwd iroh-relay >/dev/null; then
    useradd --system --user-group --home-dir /var/lib/iroh-relay \
        --no-create-home --shell /usr/sbin/nologin iroh-relay
    say "added the user iroh-relay"
fi

# The configuration, with the contact address for Let's Encrypt.
config=$work/config.toml
cp "$here/config.toml" "$config"
if grep -q '@RELAY_EMAIL@' "$config"; then
    [[ $email =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$ ]] ||
        die "Let's Encrypt needs a contact address: give one (RELAY_EMAIL), or write it in config.toml"
    sed -i "s|@RELAY_EMAIL@|$email|" "$config"
fi
install -d -m 0750 -o root -g iroh-relay /etc/iroh-relay
put "$config" /etc/iroh-relay/config.toml 0640 iroh-relay
put "$here/journald@iroh-relay.conf" /etc/systemd/journald@iroh-relay.conf 0644 root
put "$here/iroh-relay.service" /etc/systemd/system/iroh-relay.service 0644 root

# The ports, before the image's final REJECT (Oracle's Ubuntu ends its
# INPUT chain with one), kept over reboots.
accept_port() {
    local tool=$1 proto=$2 port=$3 at
    local rule=(-p "$proto" --dport "$port" -m conntrack --ctstate NEW
        -m comment --comment binbun-relay -j ACCEPT)
    "$tool" -C INPUT "${rule[@]}" 2>/dev/null && return
    at=$("$tool" -S INPUT | awk '/^-A INPUT/ { n++ } /^-A INPUT.* -j (REJECT|DROP)/ { print n; exit }')
    if [ -n "$at" ]; then
        "$tool" -I INPUT "$at" "${rule[@]}"
    else
        "$tool" -A INPUT "${rule[@]}"
    fi
    say "$tool: accepting $proto $port"
}
if ufw_active; then
    for port in "${tcp_ports[@]}"; do ufw allow "$port/tcp"; done
    for port in "${udp_ports[@]}"; do ufw allow "$port/udp"; done
else
    for tool in iptables ip6tables; do
        for port in "${tcp_ports[@]}"; do accept_port "$tool" tcp "$port"; done
        for port in "${udp_ports[@]}"; do accept_port "$tool" udp "$port"; done
    done
    netfilter-persistent save >/dev/null 2>&1 || die "netfilter-persistent save failed"
fi

# The service.
systemctl daemon-reload
systemctl enable --quiet iroh-relay.service
if [ "$changed" = 1 ] || ! systemctl is-active --quiet iroh-relay.service; then
    systemctl restart iroh-relay.service
    say "(re)started iroh-relay"
fi
sleep 2
systemctl is-active --quiet iroh-relay.service ||
    die "iroh-relay is not running: journalctl --namespace=iroh-relay -u iroh-relay"
say "iroh-relay $version is running"
