#!/usr/bin/env bash
# Validate install.sh end-to-end in a fresh Linux container (uses the locally-built
# binary instead of downloading from GitHub releases). Run from repo root:
#   bash dev/docker-install-test.sh
set -euo pipefail
cd "$(dirname "$0")/.."

GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=install-test" \
  -o dist/edge-guardian-linux-amd64 ./cmd/edge-guardian
echo "==> built linux binary"

docker run --rm --privileged -v "$PWD:/repo" debian:12-slim bash -c '
set -e
pass=0; fail=0
ok()  { echo "  ✓ $1"; pass=$((pass+1)); }
bad() { echo "  ✗ $1"; fail=$((fail+1)); }

apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq nftables >/dev/null 2>&1

echo "==> run install.sh (local binary, no systemd start)"
EDGEGUARD_BINARY=/repo/dist/edge-guardian-linux-amd64 EDGEGUARD_NO_START=1 bash /repo/install.sh >/tmp/install.log 2>&1 || { cat /tmp/install.log; exit 1; }

[ -x /usr/local/bin/edge-guardian ] && ok "binary installed to /usr/local/bin" || bad "binary missing"
/usr/local/bin/edge-guardian --version >/dev/null 2>&1 && ok "installed binary runs" || bad "binary does not run"
[ -f /etc/edge-guardian/config.toml ] && ok "starter config written" || bad "config missing"
[ "$(stat -c %a /etc/edge-guardian/config.toml)" = "600" ] && ok "config is chmod 600" || bad "config perms wrong"
[ -f /etc/systemd/system/edge-guardian.service ] && ok "systemd unit written" || bad "unit missing"
[ -d /var/lib/edge-guardian ] && ok "state dir created" || bad "state dir missing"

echo "==> nftables initialized by installer"
nft list table inet edge_guardian >/dev/null 2>&1 && ok "edge_guardian table created" || bad "table missing"
for s in blocklist4 blocklist6 blockset4 blockset6; do
  nft list set inet edge_guardian $s >/dev/null 2>&1 && ok "set $s exists" || bad "set $s missing"
done
nft list chain inet edge_guardian input | grep -q "@blockset4 drop" && ok "blockset drop rule present" || bad "blockset drop rule missing"

echo "==> idempotent: re-run install.sh keeps config + still succeeds"
echo "# user edit marker" >> /etc/edge-guardian/config.toml
EDGEGUARD_BINARY=/repo/dist/edge-guardian-linux-amd64 EDGEGUARD_NO_START=1 bash /repo/install.sh >/dev/null 2>&1
grep -q "user edit marker" /etc/edge-guardian/config.toml && ok "existing config preserved on re-run" || bad "re-run clobbered config"

echo
echo "==================== INSTALL: $pass passed, $fail failed ===================="
[ "$fail" -eq 0 ]
'
