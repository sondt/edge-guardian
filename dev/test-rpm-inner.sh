#!/usr/bin/env bash
# Runs INSIDE a rockylinux:9 container. Validates the .rpm end-to-end.
set -uo pipefail
pass=0; fail=0
ok()  { echo "  ✓ $1"; pass=$((pass+1)); }
bad() { echo "  ✗ $1"; fail=$((fail+1)); }

# rpm file names use GOARCH (amd64/arm64); the container is x86_64/aarch64.
case "$(uname -m)" in
  x86_64)  GOARCH=amd64 ;;
  aarch64) GOARCH=arm64 ;;
esac
RPM010=/repo/dist/edge-guardian-0.1.0.${GOARCH}.rpm
RPM011=/repo/dist/edge-guardian-0.1.1.${GOARCH}.rpm
echo "==> testing $GOARCH rpm ($(uname -m))"

echo "==> install nftables + the 0.1.0 rpm via dnf"
dnf install -y -q nftables >/dev/null 2>&1
dnf install -y -q "$RPM010" >/tmp/rpm.log 2>&1 && ok "dnf install rpm succeeded" || { bad "rpm install failed"; cat /tmp/rpm.log; }

echo "==> files placed"
[ -x /usr/bin/edge-guardian ] && ok "binary at /usr/bin/edge-guardian" || bad "binary missing"
/usr/bin/edge-guardian --version 2>/dev/null | grep -q '0.1.0' && ok "binary reports 0.1.0" || bad "version wrong"
[ -f /lib/systemd/system/edge-guardian.service ] && ok "systemd unit installed" || bad "unit missing"
[ -f /etc/edge-guardian/config.toml ] && ok "config installed" || bad "config missing"
[ "$(stat -c %a /etc/edge-guardian/config.toml)" = "600" ] && ok "config chmod 600" || bad "config perms = $(stat -c %a /etc/edge-guardian/config.toml)"
[ -f /usr/share/edge-guardian/config.example.toml ] && ok "config.example shipped" || bad "example missing"
[ -f /usr/share/edge-guardian/setup-nftables.sh ] && ok "setup-nftables.sh shipped" || bad "setup missing"
[ -d /var/lib/edge-guardian ] && ok "state dir created by postinstall" || bad "state dir missing"

echo "==> config marked %config(noreplace)"
rpm -qc edge-guardian 2>/dev/null | grep -q '/etc/edge-guardian/config.toml' && ok "config is %config" || bad "config not marked %config"

echo "==> postinstall initialized nftables"
nft list table inet edge_guardian >/dev/null 2>&1 && ok "edge_guardian table created" || bad "table missing"
nft list set inet edge_guardian blockset4 >/dev/null 2>&1 && ok "blockset4 interval set" || bad "blockset4 missing"

echo "==> dependency on nftables declared"
rpm -qR edge-guardian 2>/dev/null | grep -q nftables && ok "Requires: nftables" || bad "missing nftables dependency"

echo "==> daemon runs from packaged binary (dry-run)"
mkdir -p /tmp/t; printf '[log]\npaths=["/tmp/t/a.log"]\n[detection]\nbad_uri_patterns=["/wp-login"]\nthreshold=1\nwindow_secs=60\ndry_run=true\n[ban]\nduration="24h"\nwhitelist=["127.0.0.0/8"]\nnft_table="edge_guardian"\nnft_set_v4="blocklist4"\nnft_set_v6="blocklist6"\n[telegram]\nenabled=false\n[state]\npath="/tmp/t/s.json"\n[control]\nenabled=false\n' > /tmp/t/c.toml
: > /tmp/t/a.log
/usr/bin/edge-guardian -c /tmp/t/c.toml >/tmp/t/d.log 2>&1 &
DPID=$!; sleep 0.6
echo '1.2.3.4 - - [14/Jun/2026:00:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "-"' >> /tmp/t/a.log
sleep 0.6; kill -TERM $DPID 2>/dev/null; wait $DPID 2>/dev/null
grep -q 'WOULD ban' /tmp/t/d.log && ok "packaged daemon detects + would-ban" || bad "daemon did not detect"

echo "==> UPGRADE to 0.1.1 keeps an edited config"
echo '# my edit' >> /etc/edge-guardian/config.toml
dnf upgrade -y -q "$RPM011" >/tmp/up.log 2>&1 || rpm -U "$RPM011" >/tmp/up.log 2>&1
/usr/bin/edge-guardian --version 2>/dev/null | grep -q '0.1.1' && ok "binary upgraded to 0.1.1" || bad "binary not upgraded"
grep -q '# my edit' /etc/edge-guardian/config.toml && ok "edited config preserved (noreplace)" || bad "config clobbered on upgrade"

echo "==> ERASE removes binary; modified config saved as .rpmsave"
rpm -e edge-guardian >/tmp/erase.log 2>&1 && ok "rpm -e succeeded" || { bad "erase failed"; cat /tmp/erase.log; }
[ ! -x /usr/bin/edge-guardian ] && ok "binary removed on erase" || bad "binary still present"
ls /etc/edge-guardian/config.toml.rpmsave >/dev/null 2>&1 && ok "modified config saved as .rpmsave" || bad "modified config not saved on erase"

echo
echo "==================== RPM: $pass passed, $fail failed ===================="
[ "$fail" -eq 0 ]
