# Security Policy

edge-guardian runs with elevated privileges (root or `CAP_NET_ADMIN`) and parses
attacker-influenced input (log lines), so we take security reports seriously and welcome
them. Thank you for helping keep edge-guardian and its users safe.

## Supported versions

edge-guardian is pre-1.0. Only the **latest release** receives security fixes. Please upgrade
before reporting if you're on an older version.

| Version | Supported |
|---------|-----------|
| latest (0.1.x) | ✅ |
| older | ❌ |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately, one of two ways:

1. **GitHub Private Vulnerability Reporting** (preferred): on the repository, go to the
   **Security** tab → **Report a vulnerability**. This keeps the report private until a
   fix is ready.
2. **Email**: `son@giaiphapmoipro.vn` with `[edge-guardian security]` in the subject.

Please include, as best you can:

- The version (`edge-guardian --version`) and OS / nftables version.
- A description of the issue and its impact.
- Steps to reproduce, or a proof-of-concept.
- Any relevant config (with `bot_token` / `resend_api_key` / passwords **redacted**) and
  log lines (with sensitive IPs masked).

## What to expect

This is a small project, so we can't promise an enterprise SLA, but we aim to:

- Acknowledge your report within **a few days**.
- Confirm the issue and assess severity, and keep you updated on progress.
- Release a fix and credit you (if you'd like) in the release notes.

Please give us a reasonable window to ship a fix before any public disclosure
(coordinated disclosure). We won't take legal action against good-faith research that
follows this policy.

## Areas we especially care about

Because of how edge-guardian runs, these classes of bug are high-impact — reports here are
very welcome:

- **Parsing / log-injection**: anything where attacker-controlled log content (a request
  URI, an SSH username, a crafted log line) can cause edge-guardian to ban the **wrong IP**,
  skip detection, crash, or exhaust memory.
- **Privilege / firewall**: anything that lets an unintended party reach the control
  socket, or manipulate the nftables sets/rules edge-guardian manages.
- **Dashboard**: auth bypass, CSRF/XSS, session forgery, SSRF, or any way the local web
  UI exposes more than it should (it binds `127.0.0.1` by default and uses bcrypt + CSRF
  + a strict CSP).
- **Secret handling**: any path that leaks the Telegram bot token, Resend API key, or
  dashboard credentials (e.g. into logs).
- **Supply chain**: issues in the release pipeline, packages, or installer that could let
  a tampered binary reach users.

## Out of scope

- Misconfiguration by the operator (e.g. binding the dashboard to `0.0.0.0` without TLS,
  forgetting to allowlist your own admin IP, or running with an overly broad pattern set).
- Denial of service from simply sending a very high volume of traffic/log lines (rate
  limiting your log sources is the operator's responsibility; see the docs on nftables
  `limit rate` for the kernel-log rules).
- Vulnerabilities in third-party dependencies that don't affect edge-guardian — report those
  upstream (we'll still want to know if they're exploitable through edge-guardian).
