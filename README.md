# Edge Guardian

**A lightweight, single-binary edge guardian for Linux servers.** Detects scanners
and brute-force attacks from your logs, bans the source IPs at the firewall, watches
each site's health (5xx / latency / traffic), and notifies you in real time — with
zero external dependencies and a one-line install.

> Built in **Go** as a single static binary (no runtime services, no database).
> Security and edge-health share one log tail: block the bad traffic, and tell you
> when a site is degraded or down.

---

## Why edge-guardian

Every public server is hammered by automated scanners probing for `.php`, `.env`,
`/wp-login.php`, open ports, and SSH credentials. Existing tools solve this but
come with trade-offs: `fail2ban` only sees one host and is log-rule heavy;
CrowdSec is powerful but adds an agent + local API + bouncer + collections to
learn and operate.

edge-guardian targets one thing: **the simplest possible path from "I'm being scanned"
to "those IPs are blocked and I got a notification"** — a single static binary you
drop on a box, point at a log, and forget.

## Features

| Capability | Status |
|---|---|
| HTTP scanner detection (web-server access logs) | Implemented (Go) |
| nftables IP ban with auto-expiring timeout | Implemented (Go) |
| Real-time Telegram + Email (Resend) alerts (optional GeoIP/ASN) | Implemented (Go) |
| State persistence + firewall re-arm after reboot | Implemented (Go) |
| CIDR allowlist | Implemented (Go) |
| Dry-run (detect, don't block) mode | Implemented (Go) |
| `edge-guardian unban <ip>` via control socket (live) or offline | Implemented (Go) |
| Built-in local dashboard (Chi + templ + HTMX, embedded) | Implemented (Go, MVP) |
| SSH brute-force detection (auth.log / journald) | Implemented (Go) |
| Exploit-signature detection (SQLi / traversal / RCE / Log4Shell), off by default | Implemented (Go) |
| Bad-bot detection by User-Agent (sqlmap / nikto / nuclei / masscan…), off by default | Implemented (Go) |
| Rate-abuse / DoS-lite detection (per-IP request flood), off by default | Implemented (Go) |
| Port-scan detection (distinct-port counting) + honeypot ports | Implemented (Go) |
| Public blocklist import (FireHOL, Spamhaus) → nftables interval set | Implemented (Go) |
| Edge health monitoring (per-site 5xx / req-rate / p95 latency + degraded/down alerts), off by default | Implemented (Go) |
| Escalating ban + one-line install + `.deb`/`.rpm` + Docker image | Implemented |

## Quick start

One-line install (Linux, needs nftables + root). Starts in **dry-run** so it observes
without blocking until you flip `detection.dry_run = false`:

```bash
curl -fsSL https://raw.githubusercontent.com/sondt/edge-guardian/main/install.sh | sudo bash
```

Or build and install manually:

```bash
# Build (Go 1.26+). Cross-compiles from any OS — including your Mac for a Linux box:
GOOS=linux GOARCH=amd64 go build -o edge-guardian ./cmd/edge-guardian
sudo install -m 0755 edge-guardian /usr/local/bin/edge-guardian

# Configure
sudo mkdir -p /etc/edge-guardian /var/lib/edge-guardian
sudo cp config.example.toml /etc/edge-guardian/config.toml
sudo $EDITOR /etc/edge-guardian/config.toml   # set Telegram token + allowlist

# Initialise the firewall table (idempotent)
sudo bash setup-nftables.sh

# Run as a service
sudo cp edge-guardian.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now edge-guardian
sudo journalctl -u edge-guardian -f
```

Every option is documented inline in [`config.example.toml`](config.example.toml).

## How it works

```
Internet -> nginx / sshd / kernel -> logs
                                       |  (tail, follows rotation)
                                       v
                                   edge-guardian --> match? allowlisted? threshold?
                                       | yes
                                       +--> nft add element @blocklist (timeout)
                                       +--> Telegram notification
                                   nftables: ip saddr @blocklist drop
```

edge-guardian runs where the log shows the **real client IP** — typically the
edge/load-balancer node. Banned IPs are dropped at the network layer so they
never reach the application again.

## Documentation

- **Configuration** — every key is documented inline in
  [`config.example.toml`](config.example.toml).
- **Contributing** — [`CONTRIBUTING.md`](CONTRIBUTING.md) (build, test, the Linux-only
  Docker harnesses).
- **Security** — report vulnerabilities privately per [`SECURITY.md`](SECURITY.md).

## License

Released under the Apache License 2.0 — see [`LICENSE`](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
