---
name: Bug report
about: Something isn't working as expected
labels: bug
---

**What happened**
A clear description of the bug.

**Expected**
What you expected to happen.

**To reproduce**
Steps, and a config snippet if relevant (redact `bot_token` / `resend_api_key` /
passwords, and mask sensitive IPs).

**Environment**
- edge-guardian version (`edge-guardian --version`):
- OS / distro:
- nftables version (`nft --version`):
- Install method (one-liner / .deb / .rpm / Docker / from source):

**Logs**
Relevant lines from `journalctl -u edge-guardian` (run with `LOG_LEVEL=debug` if you can).

> Security vulnerability? Don't file it here — see [SECURITY.md](../../SECURITY.md).
