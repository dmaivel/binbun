#!/usr/bin/env bash
# Checks a relay that install.sh set up: from here what endpoints use
# (DNS, the certificate, HTTPS and the relay's WebSocket, the HTTP probe,
# QUIC address discovery, metrics not public), then over SSH the service
# itself (running, version, sockets, counters, recent errors). Prints a
# line per check; exits 1 if any failed.
#
#   scripts/relay/check.sh [--ip ADDRESS] [--ssh DEST | --no-ssh] [HOST]
#
# HOST: the relay's name (default relay.binbun.org). --ip: reach HOST at
# ADDRESS (before DNS has it). --ssh: where the on-host checks log in
# (default ubuntu@HOST, with RELAY_SSH as install.sh). For a relay on
# other ports or with a private CA (a test): RELAY_PORTS=HTTP,HTTPS,QUIC
# and RELAY_CACERT=FILE.
set -uo pipefail
shopt -s lastpipe

die() {
    echo "${0##*/}: $*" >&2
    exit 2
}

ip=
dest=
ssh_checks=1
host=
while [ $# -gt 0 ]; do
    case $1 in
        --ip) ip=${2:?--ip takes an address} && shift ;;
        --ssh) dest=${2:?--ssh takes a destination} && shift ;;
        --no-ssh) ssh_checks=0 ;;
        -*) die "unknown flag $1" ;;
        *) host=$1 ;;
    esac
    shift
done
host=${host:-relay.binbun.org}
dest=${dest:-ubuntu@$host}
IFS=, read -r http_port https_port quic_port <<<"${RELAY_PORTS:-80,443,7842}"
read -ra ssh <<<"${RELAY_SSH:-ssh}"

failed=0
ok() { echo "ok    $*"; }
fail() {
    echo "FAIL  $*"
    failed=1
}

# curl, reaching HOST at --ip's address and trusting RELAY_CACERT.
fetch() {
    local args=(-s --max-time 5)
    [ -n "${RELAY_CACERT:-}" ] && args+=(--cacert "$RELAY_CACERT")
    if [ -n "$ip" ]; then
        local at=$ip
        [[ $ip == *:* ]] && at="[$ip]"
        args+=(--resolve "$host:$http_port:$at" --resolve "$host:$https_port:$at"
            --resolve "$host:$quic_port:$at")
    fi
    curl "${args[@]}" "$@"
}

# DNS.
if [ -n "$ip" ]; then
    ok "reaching $host at $ip (--ip)"
else
    addresses=$(getent ahosts "$host" | awk '{ print $1 }' | sort -u | tr '\n' ' ')
    if [ -n "$addresses" ]; then
        ok "$host is ${addresses% }"
    else
        fail "$host does not resolve"
    fi
fi

# The certificate: names, issuer, days left. The relay renews it with a
# third of its life left; under a quarter, renewing is failing.
connect=${ip:-$host}
[[ $connect == *:* ]] && connect="[$connect]"
pem=$(openssl s_client -connect "$connect:$https_port" -servername "$host" </dev/null 2>/dev/null |
    openssl x509 2>/dev/null)
if [ -n "$pem" ]; then
    names=$(openssl x509 -noout -ext subjectAltName <<<"$pem" | sed -n 's/^ *//; s/DNS://g; 2p')
    issuer=$(openssl x509 -noout -issuer <<<"$pem" | sed 's/^issuer=//')
    from=$(date -d "$(openssl x509 -noout -startdate <<<"$pem" | sed 's/^notBefore=//')" +%s)
    until=$(date -d "$(openssl x509 -noout -enddate <<<"$pem" | sed 's/^notAfter=//')" +%s)
    now=$(date +%s)
    days=$(((until - now) / 86400))
    if ! openssl x509 -noout -checkhost "$host" <<<"$pem" | grep -q 'does match'; then
        fail "certificate for $names from $issuer: not for $host"
    elif [ $((4 * (until - now))) -ge $((until - from)) ]; then
        ok "certificate for $names from $issuer, $days days left"
    else
        fail "certificate for $names from $issuer: $days days left of $(((until - from) / 86400)) (renewal failing?)"
    fi
else
    fail "no TLS on $host:$https_port"
fi

# HTTPS: health, the probe endpoints use, the relay's WebSocket.
base=https://$host:$https_port
for path in /healthz /ping; do
    answer=$(fetch -o /dev/null -w '%{http_code} %{errormsg}' "$base$path")
    if [ "${answer%% *}" = 200 ]; then
        ok "$base$path: 200"
    else
        fail "$base$path: $answer"
    fi
done
code=$(fetch --http1.1 -o /dev/null -w '%{http_code}' --max-time 3 \
    -H 'Connection: Upgrade' -H 'Upgrade: websocket' -H 'Sec-WebSocket-Version: 13' \
    -H 'Sec-WebSocket-Key: YmluYnVuLXJlbGF5LWNoZWNr' -H 'Sec-WebSocket-Protocol: iroh-relay-v2' \
    "$base/relay")
if [ "$code" = 101 ]; then
    ok "$base/relay: upgrades to iroh-relay-v2"
else
    fail "$base/relay: ${code:-no answer} (not a WebSocket upgrade)"
fi

# HTTP: the captive-portal probe.
challenge=binbunCheck$RANDOM
answer=$(fetch -o /dev/null -D - -H "X-Iroh-Challenge: $challenge" \
    "http://$host:$http_port/generate_204" | tr -d '\r')
if grep -q '^HTTP/[0-9.]* 204' <<<"$answer" &&
    grep -qi "^x-iroh-response: response $challenge\$" <<<"$answer"; then
    ok "http://$host:$http_port/generate_204: 204, challenge answered"
else
    fail "http://$host:$http_port/generate_204: $(head -1 <<<"$answer")"
fi

# QUIC address discovery (UDP): a QUIC handshake with its ALPN and the
# certificate checked (OpenSSL 3.2 and later speak QUIC).
if openssl s_client -help 2>&1 | grep -q -- '-quic'; then
    trust=()
    [ -n "${RELAY_CACERT:-}" ] && trust=(-CAfile "$RELAY_CACERT")
    handshake=$(timeout 5 openssl s_client -quic -alpn /iroh-qad/0 -connect "$connect:$quic_port" \
        -servername "$host" -verify_hostname "$host" -verify_return_error "${trust[@]}" \
        </dev/null 2>&1)
    if grep -q '^ALPN protocol: /iroh-qad/0' <<<"$handshake" &&
        grep -qx "Verified peername: $host" <<<"$handshake"; then
        ok "udp $quic_port: QUIC address discovery answers, certificate verified"
    elif grep -q '^ALPN protocol: /iroh-qad/0' <<<"$handshake"; then
        fail "udp $quic_port: QUIC address discovery answers, but $(grep -m1 '^Verification error' <<<"$handshake")"
    else
        fail "udp $quic_port: no QUIC address discovery (security list, firewall?): $(grep -m1 -i 'error' <<<"$handshake")"
    fi
else
    echo "skip  udp $quic_port: this openssl has no QUIC (the on-host check sees the socket)"
fi

# Metrics stay on the machine.
if fetch -o /dev/null --max-time 3 "http://$host:9090/metrics" 2>/dev/null; then
    fail "metrics are public on $host:9090"
else
    ok "metrics not reachable from here"
fi

# On the machine (as root: sudo).
if [ "$ssh_checks" = 1 ]; then
    pinned=$(sed -n 's/^version=//p' "$(dirname "${BASH_SOURCE[0]}")/setup.sh")
    # shellcheck disable=SC2016 # expanded on the relay's machine
    "${ssh[@]}" -o BatchMode=yes "$dest" sudo -n bash -s -- "$http_port" "$https_port" "$quic_port" "$pinned" <<'EOF' |
ok() { echo "ok    $*"; }
fail() { echo "FAIL  $*"; }
state=$(systemctl is-active iroh-relay.service)
if [ "$state" = active ]; then
    ok "service iroh-relay: active since $(systemctl show -P ActiveEnterTimestamp iroh-relay.service)"
else
    fail "service iroh-relay: $state"
fi
installed=$(/usr/local/bin/iroh-relay --version)
if [ "$installed" = "iroh-relay $4" ]; then
    ok "$installed"
else
    fail "$installed, setup.sh pins $4: run install.sh"
fi
for socket in tcp:$1 tcp:$2 udp:$3; do
    if ss -Hln --"${socket%%:*}" "sport = :${socket#*:}" | grep -q .; then
        ok "listening on ${socket%%:*} ${socket#*:}"
    else
        fail "nothing listening on ${socket%%:*} ${socket#*:}"
    fi
done
if metrics=$(curl -sS --max-time 5 http://127.0.0.1:9090/metrics); then
    ok "since start: $(awk '$1 ~ /^relayserver_(accepts|unique_client_keys|bytes_recv|bytes_sent|bytes_rx_ratelimited|qad_connections)_total$/ { sub(/^relayserver_/, "", $1); sub(/_total$/, "", $1); printf "%s%s %s", sep, $1, $2; sep = ", " }' <<<"$metrics")"
else
    fail "no metrics on 127.0.0.1:9090"
fi
errors=$(journalctl --namespace=iroh-relay -u iroh-relay.service --since -1h -q --no-pager -o cat | grep 'ERROR')
if [ -z "$errors" ]; then
    ok "no errors logged in the last hour"
else
    echo "warn  $(wc -l <<<"$errors") error(s) logged in the last hour (sudo journalctl --namespace=iroh-relay), the last:"
    echo "      $(tail -1 <<<"$errors" | cut -c1-300)"
fi
EOF
        while IFS= read -r line; do
            echo "$line"
            [[ $line == FAIL* ]] && failed=1
        done
    [ "${PIPESTATUS[0]}" = 0 ] || fail "ssh $dest"
fi

exit "$failed"
