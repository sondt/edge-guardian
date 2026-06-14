#!/usr/bin/env bash
# Runs INSIDE a debian:12 container. Validates the .deb end-to-end.
set -uo pipefail
pass=0; fail=0
ok()  { echo "  ✓ $1"; pass=$((pass+1)); }
bad() { echo "  ✗ $1"; fail=$((fail+1)); }

ARCH="$(dpkg --print-architecture)"   # amd64 or arm64 — match the container
DEB010=/repo/dist/edge-guardian_0.1.0_${ARCH}.deb
DEB011=/repo/dist/edge-guardian_0.1.1_${ARCH}.deb
echo "==> testing $ARCH packages"

echo "==> install nftables (dependency) + the 0.1.0 .deb"
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq nftables >/dev/null 2>&1
dpkg -i "$DEB010" >/tmp/dpkg.log 2>&1 && ok "dpkg -i succeeded" || { bad "dpkg -i failed"; cat /tmp/dpkg.log; }

echo "==> files placed"
[ -x /usr/bin/edge-guardian ] && ok "binary at /usr/bin/edge-guardian" || bad "binary missing"
/usr/bin/edge-guardian --version 2>/dev/null | grep -q '0.1.0' && ok "binary reports version 0.1.0" || bad "version wrong"
[ -f /lib/systemd/system/edge-guardian.service ] && ok "systemd unit installed" || bad "unit missing"
[ -f /etc/edge-guardian/config.toml ] && ok "config installed" || bad "config missing"
[ "$(stat -c %a /etc/edge-guardian/config.toml)" = "600" ] && ok "config chmod 600" || bad "config perms = $(stat -c %a /etc/edge-guardian/config.toml)"
[ -f /usr/share/edge-guardian/config.example.toml ] && ok "config.example doc shipped" || bad "doc missing"
[ -f /usr/share/edge-guardian/setup-nftables.sh ] && ok "setup-nftables.sh shipped" || bad "setup script missing"
[ -d /var/lib/edge-guardian ] && ok "state dir created by postinstall" || bad "state dir missing"

echo "==> config is a dpkg conffile (won't be clobbered on upgrade)"
dpkg-query --showformat='${Conffiles}' --show edge-guardian 2>/dev/null | grep -q '/etc/edge-guardian/config.toml' && ok "config registered as conffile" || bad "config not a conffile"

echo "==> postinstall initialized nftables"
nft list table inet edge_guardian >/dev/null 2>&1 && ok "edge_guardian table created" || bad "table missing"
nft list set inet edge_guardian blockset4 >/dev/null 2>&1 && ok "blockset4 interval set created" || bad "blockset4 missing"

echo "==> dependency on nftables declared"
dpkg-deb -f "$DEB010" Depends | grep -q nftables && ok "Depends: nftables" || bad "missing nftables dependency"

echo "==> daemon actually runs from the packaged binary (dry-run, brief)"
mkdir -p /tmp/t; printf '[log]\npaths=["/tmp/t/a.log"]\n[detection]\nbad_uri_patterns=["/wp-login"]\nthreshold=1\nwindow_secs=60\ndry_run=true\n[ban]\nduration="24h"\nwhitelist=["127.0.0.0/8"]\nnft_table="edge_guardian"\nnft_set_v4="blocklist4"\nnft_set_v6="blocklist6"\n[telegram]\nenabled=false\n[state]\npath="/tmp/t/s.json"\n[control]\nenabled=false\n' > /tmp/t/c.toml
: > /tmp/t/a.log
/usr/bin/edge-guardian -c /tmp/t/c.toml >/tmp/t/d.log 2>&1 &
DPID=$!; sleep 0.6
echo '1.2.3.4 - - [14/Jun/2026:00:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "-"' >> /tmp/t/a.log
sleep 0.6; kill -TERM $DPID 2>/dev/null; wait $DPID 2>/dev/null
grep -q 'WOULD ban' /tmp/t/d.log && ok "packaged daemon detects + would-ban" || bad "daemon did not detect"

echo "==> UPGRADE to 0.1.1 keeps an edited config"
echo '# my edit' >> /etc/edge-guardian/config.toml
dpkg -i "$DEB011" >/tmp/up.log 2>&1 && ok "upgrade install ok" || { bad "upgrade failed"; cat /tmp/up.log; }
/usr/bin/edge-guardian --version 2>/dev/null | grep -q '0.1.1' && ok "binary upgraded to 0.1.1" || bad "binary not upgraded"
grep -q '# my edit' /etc/edge-guardian/config.toml && ok "edited config preserved across upgrade" || bad "config clobbered on upgrade"

echo "==> REMOVE keeps config; PURGE removes it"
apt-get remove -y -qq edge-guardian >/dev/null 2>&1
[ ! -x /usr/bin/edge-guardian ] && ok "binary removed on remove" || bad "binary still present after remove"
[ -f /etc/edge-guardian/config.toml ] && ok "config kept after remove (conffile)" || bad "config gone after plain remove"
apt-get purge -y -qq edge-guardian >/dev/null 2>&1
[ ! -f /etc/edge-guardian/config.toml ] && ok "config removed on purge" || bad "config left after purge"

echo
echo "==================== DEB: $pass passed, $fail failed ===================="
[ "$fail" -eq 0 ]
