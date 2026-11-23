# relay.binbun.org

binbun's own iroh relay: `iroh-relay` 1.4.1 (n0's release binary, its
SHA-256 pinned in `setup.sh`) on an Oracle always-free VM (Ubuntu 24.04,
user `ubuntu`; aarch64 or x86-64), as `relay.binbun.org` and
`us-east.relay.binbun.org`. Peers
that cannot reach each other directly go through it, and it tells each
endpoint the address it is seen from (QUIC address discovery) for hole
punching.

| File | Installed as |
|---|---|
| `install.sh HOST` | run here: copies the files below to HOST over SSH and runs `setup.sh` with sudo; again any time, it changes only what differs |
| `setup.sh` | runs on the VM: the binary in `/usr/local/bin`, the `iroh-relay` system user, the files below, the firewall, the service |
| `config.toml` | `/etc/iroh-relay/config.toml`: Let's Encrypt for both names, QUIC address discovery, metrics on loopback, limits |
| `iroh-relay.service` | the systemd unit: only `CAP_NET_BIND_SERVICE`, `NoNewPrivileges`, `ProtectSystem=strict`, a syscall filter and the rest (`systemd-analyze security`: 1.4, OK) |
| `journald@iroh-relay.conf` | the service's own journal, in memory only |
| `check.sh [HOST]` | run here: checks the relay from outside and over SSH |

`.github/workflows/relay.yml` runs `check.sh --no-ssh` every hour and
fails (GitHub mails whoever last changed its schedule) when the relay
stops answering: Oracle may reclaim an idle always-free VM without
notice.

## Setting it up

1. Create the VM (Ubuntu 24.04, a reserved public IPv4; IPv6 if the VCN
   has it). The always-free shapes both work: A1.Flex (aarch64, up to 4
   cores and 24 GB, often out of capacity) or E2.1.Micro (x86-64, 1 GB).
2. In the subnet's security list (or the VM's NSG), stateful ingress from
   `0.0.0.0/0` (and `::/0`): **TCP 443, TCP 80, UDP 7842**. SSH (TCP 22)
   is there already. Nothing else; metrics (9090) stay on the VM.
3. DNS: A (and AAAA) records for `relay.binbun.org` and
   `us-east.relay.binbun.org` to the VM. Both must resolve before the
   first start: Let's Encrypt checks each name on port 443 (TLS-ALPN-01),
   and allows 5 failed checks per name per hour.
4. `RELAY_EMAIL=you@example.org scripts/relay/install.sh 203.0.113.7`
   (the address Let's Encrypt writes to about expiry; or write it in
   `config.toml`).
5. `scripts/relay/check.sh relay.binbun.org` (`--ip 203.0.113.7` while
   DNS is new). It exits 1 if anything failed.

When binbun moves to another iroh, `install.sh` refuses until `setup.sh`
pins the matching release: set `version=` and both SHA-256s (the
release's digests on GitHub), then run `install.sh` again.

## Ports

| Port | What |
|---|---|
| TCP 443 | the relay (WebSocket at `/relay`; `/ping`, `/healthz`), and Let's Encrypt's TLS-ALPN-01 check: no certbot, no port 80 for ACME |
| TCP 80 | plain HTTP `/generate_204` only: the captive-portal probe endpoints run |
| UDP 7842 | QUIC address discovery |

On the VM, `setup.sh` accepts these in iptables before Oracle's final
REJECT and saves them (`netfilter-persistent`); Oracle says not to use
ufw on its images. Where ufw is already active, it uses ufw.

## What it sees, what it keeps

It sees the endpoint ids (public keys) connected to it, their IP
addresses and ports, which endpoint sends to which, when, and how much.
It never sees content: what it forwards is QUIC encrypted end to end
between the endpoints (TLS 1.3 with their keys), and binbun's data is
encrypted again with project keys underneath.

It keeps nothing beyond operation. It logs errors only (`RUST_LOG=error`;
iroh-relay's warnings name client addresses and endpoint ids, so keep it
there) into a journal of its own, held in memory: gone at reboot, at most
2 days or 16 MB (`sudo journalctl --namespace=iroh-relay`). Its metrics
are totals (connections, bytes), on loopback. On disk: the Let's Encrypt
account key and certificate (`/var/lib/iroh-relay`). Keep the VCN's flow
logs off.

## Limits

Each endpoint may send 2 MiB/s through it, in bursts up to 8 MiB.
iroh-relay 1.4.1 has no limit on new connections. Any iroh endpoint may
use it, as with n0's relays.
