# Why I built edge-guardian

*A single-binary intrusion-prevention daemon for Linux — and the handful of opinions that
shaped it.*

Every server I've ever put on the public internet started getting attacked within minutes.
Not "if a determined adversary targets you" attacked — just the constant, ambient noise of
bots sweeping the entire IPv4 space, knocking on every door: `/.env`, `/wp-login.php`,
`/.git/config`, `/phpmyadmin/`, and an endless stream of SSH login attempts for `root`,
`admin`, `oracle`, `postgres`.

You can ignore it — most of it bounces off — but it grates. So you reach for a tool. And
that's where it always got annoying.

## The tradeoff nobody loved

**fail2ban** is the old reliable. It works. But it only sees the host it's on, it leans
hard on regex rules and jail config, it gets awkward the moment you have more than one box,
and there's no UI — you're reading logs to find out what it did.

**CrowdSec** is genuinely impressive, with a crowd-sourced blocklist that's a real moat. But
running it means standing up an agent, a Local API, a bouncer, and "collections," and
learning the model. And the part you actually want to look at — the pretty console — is the
paid tier.

Both are good tools. But for the specific job of *"a person with a few servers who wants
basic protection without a project"*, both felt like more than I wanted to carry.

## One sentence became the spec

> The shortest possible path from **"my server is being scanned"** to **"those IPs are
> blocked and I got a notification."**

That's it. Everything else is in service of that sentence. If a decision made that path
shorter or more trustworthy, it was in. If it added a service to run or a concept to learn,
it had to fight for its place.

## The product has a personality: calm until something happens

This is the line I kept coming back to. A security tool that's constantly flashing and
beeping trains you to ignore it. I wanted the opposite: something that sits quiet and
neutral — like a precision instrument — and only gets loud when it actually matters. When
the dashboard's signal turns red, it should *mean* something, because it's rare.

That idea drove the whole aesthetic, right down to the dashboard's signature: a "Sentinel
line," a live seismograph of your server's exposure that stays flat and grey until a scan
spikes it red.

## The opinions that shaped the code

**One static binary, no moving parts.** Go compiles to a single static binary with no cgo,
and cross-compiles trivially — I build for a Linux box from my Mac with one command. So:
no database, no agent, no companion services. State is one JSON file. The whole thing is one
process you drop on a server and forget. This is the entire reason it can have a one-line
install that actually works.

**nftables sets are the right primitive.** Instead of managing a firewall rule per banned
IP (the iptables way, or pulling in ipset), edge-guardian keeps *one* rule — `ip saddr
@blocklist drop` — and bans are just elements added to a set with a per-entry timeout. The
kernel expires them itself; no cron, no cleanup. Lookups stay fast with tens of thousands of
entries. After a reboot the set is empty, so on start the daemon re-arms it from state. One
rule, IPs are data.

**One pipeline, many detectors.** Read a log line → decide → enforce → notify. HTTP
scanners, SSH brute-force, port scans, honeypot ports — they all flow through the same path.
Adding a source is a parser plus a threshold, never a rewrite. (A nice side effect: because
the detectors' log formats are disjoint, the daemon just runs all of them on every line and
at most one matches — no routing needed.)

**The dashboard ships free, on purpose.** This is the one place I spent "extra" effort, and
it's deliberate. It's the thing fail2ban lacks and CrowdSec charges for, so it's the reason
to pick edge-guardian. It's embedded in the binary (Chi + templ + HTMX, server-rendered, no
build step, all assets baked in), served on localhost behind bcrypt + CSRF + a strict CSP.
No Grafana to wire up, no paywall.

**Trust is a feature, so dry-run is non-negotiable.** An auto-banning daemon that locks you
out of your own server is worse than no daemon. So there's a CIDR allowlist checked before
*any* ban, and a dry-run mode that detects, logs, and alerts but never touches the firewall.
You run it on production for a few days, watch what it *would* have done, tune your
patterns, and only then flip the switch. Without that, nobody sane arms an automated IPS on
a live box.

**A couple of small wins I'm fond of.** The SSH detector is hardened against the classic
username log-injection trick (it reads the *last* `from <ip>` sshd writes, so a crafted
username can't frame an innocent IP). And the GeoIP reader talks to maxminddb directly
instead of through the usual library, which means it works with the *free*, CC-licensed
IP-location databases — not just MaxMind's, which need an account.

**Honest about the business.** The plan is open-core: the self-hosted engine stays free and
Apache-2.0 forever; the eventual paid piece is centralized management for people running
many nodes. I'm not pretending otherwise. And there's no crowd-sourced blocklist yet — that
has a real cold-start problem — so today it leans on public lists (FireHOL, Spamhaus) plus
your own server's detections.

## Where it is

It's early — v0.1.0. But the free, single-node core is real and tested: I validated the
actual nftables enforcement, the detectors, and the `.deb`/`.rpm`/Docker packaging on real
Linux in CI, not just in unit tests. It's Linux + nftables only, and a couple of detectors
(port scan, honeypot) ask you to route nftables log lines to a file. The name, `edge-guardian`,
is a leftover prefix from an internal project and will probably change.

If any of this resonates — if you've also bounced off the "fiddly vs. heavy" tradeoff —
I'd love for you to try it and tell me where it falls short.

```
curl -fsSL https://raw.githubusercontent.com/sondt/edge-guardian/main/install.sh | sudo bash
```

It starts in dry-run. It won't touch your firewall until you tell it to.

→ **https://github.com/sondt/edge-guardian** · Apache-2.0 · built in Go
