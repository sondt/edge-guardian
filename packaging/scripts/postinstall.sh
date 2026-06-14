#!/bin/sh
# edge-guardian postinstall — runs on install AND upgrade (deb: configure; rpm: $1>=1).
set -e

# Runtime state dir.
mkdir -p /var/lib/edge-guardian
chmod 0750 /var/lib/edge-guardian

# Protect the config (may hold telegram/email/resend secrets).
[ -f /etc/edge-guardian/config.toml ] && chmod 0600 /etc/edge-guardian/config.toml || true

# Initialize the nftables table/sets/drop-rules (idempotent). Best-effort: a build/CI
# environment may lack nft or netfilter — don't fail the install over it.
if command -v nft >/dev/null 2>&1; then
    nft list table inet edge_guardian >/dev/null 2>&1 || nft add table inet edge_guardian || true
    nft list set inet edge_guardian blocklist4 >/dev/null 2>&1 || nft add set inet edge_guardian blocklist4 '{ type ipv4_addr; flags timeout; }' || true
    nft list set inet edge_guardian blocklist6 >/dev/null 2>&1 || nft add set inet edge_guardian blocklist6 '{ type ipv6_addr; flags timeout; }' || true
    nft list set inet edge_guardian blockset4 >/dev/null 2>&1 || nft add set inet edge_guardian blockset4 '{ type ipv4_addr; flags interval; }' || true
    nft list set inet edge_guardian blockset6 >/dev/null 2>&1 || nft add set inet edge_guardian blockset6 '{ type ipv6_addr; flags interval; }' || true
    if nft add chain inet edge_guardian input '{ type filter hook input priority -10; policy accept; }' 2>/dev/null || nft list chain inet edge_guardian input >/dev/null 2>&1; then
        nft flush chain inet edge_guardian input 2>/dev/null || true
        nft add rule inet edge_guardian input ip saddr @blocklist4 drop 2>/dev/null || true
        nft add rule inet edge_guardian input ip6 saddr @blocklist6 drop 2>/dev/null || true
        nft add rule inet edge_guardian input ip saddr @blockset4 drop 2>/dev/null || true
        nft add rule inet edge_guardian input ip6 saddr @blockset6 drop 2>/dev/null || true
    fi
fi

# Register the unit. Enable (so it survives reboot) but DON'T start automatically —
# the admin should review /etc/edge-guardian/config.toml first (it ships in safe dry-run).
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable edge-guardian.service >/dev/null 2>&1 || true
fi

echo "edge-guardian installed. Review /etc/edge-guardian/config.toml (ships in dry-run), then:"
echo "  sudo systemctl start edge-guardian  &&  journalctl -u edge-guardian -f"

exit 0
