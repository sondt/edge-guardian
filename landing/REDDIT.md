# Reddit launch posts — edge-guardian

Two posts, two cultures. r/selfhosted loves screenshots and "I made a thing"; r/sysadmin
is more skeptical of self-promotion and cares about operational safety. **Disclose that
you're the author** (both subs require/expect it), read each sub's self-promo rules, and
don't cross-post the identical text the same day. **Public the repo first.**

**Screenshots to attach** (Reddit posts live or die on the image):
1. The dashboard — run `make demo` and screenshot the Overview (Sentinel line + readout
   cards + feed). This is the hook.
2. The bans ledger (detector + reason + origin + unban).
3. Optional: `landing/og.png` as the preview, or a terminal showing the one-line install.

---

## r/selfhosted

**Title:**

> edge-guardian – a single-binary intrusion-prevention daemon for Linux, with a built-in dashboard (free)

**Body:**

Hey r/selfhosted — I'm the author. I got tired of every VPS I spin up immediately getting
hammered by bots probing `/.env`, `/wp-login.php`, and SSH, so I built a small tool to deal
with it the way I actually wanted: one binary, point it at your logs, done.

**edge-guardian** tails your logs, detects scanners and brute-force, and bans the source IPs at
the firewall (nftables) — then shows you everything in a dashboard that's included free.

What it does:

- 🔭 Detects **HTTP scanners**, **SSH brute-force**, **port scans**, and **honeypot-port**
  hits — all through one pipeline.
- 🧱 Bans at the kernel via an **nftables set with timeouts**, so bans expire themselves.
  **Escalating** bans for repeat offenders (a day → a week → a month → forever).
- 📊 A **built-in dashboard** (embedded in the binary, served on localhost) with a live
  "Sentinel line", a banned-IP ledger, and a feed. *[screenshot]*
- 🔔 **Telegram + email** alerts, with country/ASN from offline GeoIP (works with the free
  databases, no MaxMind account).
- 🛡️ **Public blocklist import** (FireHOL/Spamhaus) to block known-bad ranges proactively.
- ✅ **Dry-run mode** + a CIDR allowlist so you can run it for a few days and trust it
  before it ever touches your firewall — and never lock yourself out.

Why another one of these? fail2ban only sees one host and has no UI; CrowdSec is great but
it's an agent + local API + bouncer + collections, and the nice dashboard is paid. I wanted
the boring, simple version with the dashboard included.

It's one static Go binary — no database, no agent, no cloud, **no telemetry**. Install is a
one-liner, or `.deb`/`.rpm` (amd64 + arm64), or a Docker image. Apache-2.0.

```
curl -fsSL https://raw.githubusercontent.com/sondt/edge-guardian/main/install.sh | sudo bash
```

Repo: https://github.com/sondt/edge-guardian

It's early (v0.1.0) but the core is tested on real Linux. Would love feedback from people
running small fleets — especially on false-positive risk and whether the dashboard actually
matters to you. Happy to answer anything in the comments. (Also: the name is a leftover from
an old project and probably needs to change — open to ideas. 😅)

---

## r/sysadmin

**Title:**

> Sharing a tool I built: edge-guardian – single-binary IPS for Linux (nftables, dry-run, no telemetry)

**Body:**

Disclosure: I wrote this, and I'm sharing it for feedback, not pitching a product — it's
free and Apache-2.0.

Short version: edge-guardian is a single static Go binary that reads logs, detects
scanners/brute-force, and bans source IPs in an nftables set. It's deliberately boring to
operate — closer to "fail2ban as one binary with a UI" than to CrowdSec's agent/LAPI/bouncer
stack.

The parts I think this crowd will care about:

- **Won't lock you out.** A CIDR allowlist is checked before any ban, and there's a
  **dry-run mode** that detects + alerts but doesn't touch nftables — so you can run it on
  prod and watch for a few days before arming it. Bans auto-expire via nftables timeouts;
  `edge-guardian unban <ip>` cleans up state + firewall in one shot.
- **No moving parts.** No database, no agent, no daemon zoo, no external calls except the
  Telegram/email/blocklist endpoints you configure. **No telemetry.** State is one JSON
  file; the firewall is re-armed from it after reboot.
- **Native nftables**, via netlink — one rule, IPs live in a timeout set, fast at scale.
- **Packaged properly.** `.deb`/`.rpm` (amd64 + arm64) with conffile/`%config(noreplace)`
  handling, a systemd unit, and a postinstall that initializes the firewall. Or a container.
- Detection covers HTTP scanner paths, SSH brute-force (hardened against the username
  log-injection trick), distinct-port scans, and honeypot ports. Plus FireHOL/Spamhaus
  blocklist import and escalating bans for repeat offenders.
- There's a local dashboard (binds 127.0.0.1; bcrypt + CSRF + strict CSP) if you want a UI,
  but it's optional — the daemon does its job headless.

Honest caveats: it's v0.1.0; Linux + nftables only (no iptables/Windows); the HTTP detector
needs to run where the real client IP is logged (your edge/LB); and port-scan/honeypot rely
on routing nftables `log` to a file via journald/rsyslog.

Repo + docs: https://github.com/sondt/edge-guardian

I'd genuinely value a sanity check on the detection defaults and the nftables approach from
people who run this stuff for a living. Thanks.
