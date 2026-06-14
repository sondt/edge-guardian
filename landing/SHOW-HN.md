# Show HN launch kit — edge-guardian

Everything to post edge-guardian on Hacker News. HN rewards honesty, technical detail, and a
fast, gracious presence in the comments — and punishes marketing speak and overclaiming.
Copy below is written in that spirit. **Make the GitHub repo public first** (the install
command and links must resolve).

---

## Title

Pick one. Keep it factual — no "revolutionary", no superlatives.

**Recommended:**

> Show HN: edge-guardian – single-binary intrusion prevention for Linux, with a dashboard

Alternates:

> Show HN: edge-guardian – fail2ban-style IP banning as one Go binary (nftables, with a UI)

> Show HN: edge-guardian – bans scanners and SSH brute-force at nftables, with a free dashboard

## URL to submit

Submit the **repo** (HN likes seeing the code): `https://github.com/sondt/edge-guardian`
Then post the comment below immediately as the first reply.

(If you'd rather lead with the landing page, submit that URL instead — but have the repo
link prominent. HN will look for the source.)

---

## First comment (post this right after submitting)

Hi HN — I built edge-guardian because protecting a small fleet of Linux servers still feels
like a choice between fiddly and heavy.

fail2ban is proven, but it only sees one host, leans hard on regex rules, and has no UI.
CrowdSec is genuinely powerful, but you're standing up an agent, a local API, a bouncer,
and collections — and the nice console is the paid part. I wanted the shortest path from
"my server is being scanned" to "those IPs are blocked and I got a notification," with a
dashboard included for free.

So edge-guardian is one static Go binary (no cgo, ~8 MB, cross-compiles from a Mac for any
Linux). No database, no agent, no external service — state is a single JSON file. It tails
your logs, decides, and bans at the kernel via an nftables set with per-entry timeouts
(so bans expire themselves; no cron). It re-arms the firewall from state after a reboot.

What it detects today, all through one pipeline:

- HTTP scanners — the `/.env`, `/wp-login.php`, `/.git` probes a non-PHP stack never
  serves. Ban on the first hit.
- SSH brute-force from auth.log/journald (hardened against the classic username
  log-injection — it reads the last `from <ip>` sshd writes, so a crafted username can't
  frame an innocent IP).
- Port scans, by counting *distinct* destination ports per source (hammering one port
  isn't a scan; sweeping many is).
- Honeypot ports — touch a decoy, get banned instantly.

Plus: escalating bans for repeat offenders (a day → a week → a month → permanent),
Telegram + email alerts, public blocklist import (FireHOL/Spamhaus) into an nftables
interval set, and offline GeoIP that also works with the *free* sapics databases, not
just MaxMind (I read the mmdb directly to get around geoip2's database-type guard).

The dashboard is the part I had the most fun with — it's embedded in the binary (Chi +
templ + HTMX, served on localhost, bcrypt + CSRF + strict CSP), and the signature is a
"Sentinel line": a live trace of the server's exposure that stays flat and quiet until
something spikes. Calm until something happens.

Two deliberate safety choices, because an auto-banning daemon that locks you out is
useless: a CIDR allowlist that's checked before any ban, and a **dry-run mode** that
detects, logs, and alerts but doesn't touch the firewall — so you can run it on prod for
a few days and trust it before you arm it.

Install is one line (`curl … | sudo bash`), or .deb/.rpm (amd64 + arm64), or a Docker
image. It starts in dry-run. Apache-2.0.

Honest status and limits:

- It's early (v0.1.0). The free, single-node core is solid and tested — I validated the
  real nftables enforcement, detection, and the packages on actual Linux in CI — but it's
  young.
- The eventual plan is open-core: the self-hosted engine stays free; a future paid piece
  is centralized management for many nodes. There's no crowd-sourced blocklist yet (the
  cold-start problem is real), so today it leans on public lists + your own detections.
- The HTTP detector has to run where the real client IP is logged (your edge/LB).
- Port-scan and honeypot need you to route nftables `log` lines to a file (journald or
  rsyslog) for it to read — documented, but it's a step.
- Linux + nftables only. No iptables, no Windows.
- The name: "edge-guardian" is a leftover prefix from an internal project. I know it's not
  great for a standalone tool — open to suggestions.

I'd love feedback on the detection defaults (false-positive risk), the nftables approach,
and whether "dashboard in the free tier" actually changes the calculus for you vs.
fail2ban/CrowdSec. Repo: https://github.com/sondt/edge-guardian

---

## Prepared replies (HN will likely ask these — answer fast and honestly)

**"How is this different from fail2ban?"**
> Mostly: one binary instead of a Python install + jail/filter config, a dashboard, and
> native nftables sets (one rule, IPs are data) instead of per-IP rules. fail2ban is more
> mature and flexible with arbitrary log sources; edge-guardian trades some of that
> flexibility for a much shorter setup and a UI. If fail2ban already works for you, you
> probably don't need this.

**"How is this different from CrowdSec?"**
> CrowdSec is more capable and has the crowd-sourced blocklist, which is its real moat.
> edge-guardian isn't trying to beat that — it's betting on being radically simpler to run and
> shipping the dashboard free. No agent/LAPI/bouncer/collections to learn; it's one
> process.

**"Why nftables only / no iptables?"**
> nftables sets with timeouts are exactly the right primitive: one rule, IPs live in a
> set, expiry is built in, lookups are fast at scale. iptables would mean managing
> thousands of rules or pulling in ipset. nftables is the default on every current
> distro. I'd rather do one thing well than maintain two backends.

**"Is the dashboard safe to expose?"**
> It binds 127.0.0.1 by default and is meant to go behind an SSH tunnel or a TLS reverse
> proxy. Auth is bcrypt + an HMAC-signed session cookie, every write is CSRF-protected,
> there's a strict CSP, and it ships no inline scripts. It never defaults to 0.0.0.0.

**"`curl | sudo bash` — really?"**
> Fair. The script is short and readable, and there are .deb/.rpm and a Docker image if
> you'd rather not pipe to a shell. The installer also starts in dry-run, so the first
> thing it does is *not* touch your firewall.

**"What stops it from banning a legitimate IP / locking me out?"**
> A CIDR allowlist checked before any ban (put your office/VPN/monitoring there), and
> dry-run mode to observe before enabling. Bans also auto-expire via nftables timeouts,
> and `edge-guardian unban <ip>` removes one cleanly. The defaults target paths/behaviors a
> normal client never hits, so false positives are designed to be near-zero — but you
> should run dry-run first.

**"Go binary size / dependencies?"**
> ~8 MB static, no cgo. Third-party deps are minimal and listed in go.mod (nftables via
> netlink, a tail library, TOML, maxminddb, chi/templ for the UI). Most of it is stdlib.

**"Telemetry?"**
> None. It makes no outbound calls except the ones you configure (Telegram/email, and the
> blocklist URLs you point it at).
