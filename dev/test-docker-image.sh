#!/usr/bin/env bash
# Build the edge-guardian image and validate it runs + bans for real (nftables). From repo:
#   bash dev/test-docker-image.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> building image edge-guardian:test"
docker build -q -t edge-guardian:test . >/dev/null

echo "==> image sanity"
ver="$(docker run --rm --entrypoint /usr/bin/edge-guardian edge-guardian:test --version)"
echo "  $ver" | grep -q 'edge-guardian' && echo "  ✓ entrypoint runs --version" || { echo "  ✗ version failed"; exit 1; }
docker run --rm --entrypoint sh edge-guardian:test -c 'command -v nft >/dev/null' && echo "  ✓ nft present in image" || { echo "  ✗ nft missing"; exit 1; }

echo "==> run the image with --privileged and prove it bans into real nftables"
docker run --rm --privileged --entrypoint bash -v "$PWD:/repo" edge-guardian:test -c '
set -e
pass=0; fail=0
ok(){ echo "  ✓ $1"; pass=$((pass+1)); }
bad(){ echo "  ✗ $1"; fail=$((fail+1)); }

# Initialize the firewall using the bundled script (honeypot on :2323).
EG_SERVICE_PORTS="22,80,443" EG_HONEYPOT_PORTS="2323" bash /usr/share/edge-guardian/setup-nftables.sh >/dev/null
nft list table inet edge_guardian >/dev/null 2>&1 && ok "bundled setup created the table" || bad "table missing"

mkdir -p /run/t
NFLOG=/run/t/netfilter.log; : > "$NFLOG"
cat > /run/t/config.toml <<EOF
[log]
paths = ["/run/t/access.log"]
[detection]
bad_uri_patterns = ["/wp-login"]
threshold = 1
window_secs = 60
dry_run = false
[ban]
duration = "24h"
whitelist = ["127.0.0.0/8","::1/128"]
nft_table = "edge_guardian"
nft_set_v4 = "blocklist4"
nft_set_v6 = "blocklist6"
[telegram]
enabled = false
[honeypot]
enabled = true
paths = ["/run/t/netfilter.log"]
log_prefix = "EDGEGUARD-HONEYPOT"
[state]
path = "/run/t/state.json"
[control]
enabled = false
EOF
: > /run/t/access.log

/usr/bin/edge-guardian -c /run/t/config.toml >/run/t/d.log 2>&1 &
PID=$!; sleep 1

# http scanner → real ban
echo "185.220.101.5 - - [14/Jun/2026:00:00:00 +0000] \"GET /wp-login.php HTTP/1.1\" 404 0 \"-\" \"-\"" >> /run/t/access.log
# honeypot → real ban
echo "host kernel: EDGEGUARD-HONEYPOT IN=eth0 SRC=45.13.22.7 DST=10.0.0.1 PROTO=TCP SPT=5 DPT=2323 SYN" >> "$NFLOG"
sleep 1.2

nft list set inet edge_guardian blocklist4 | grep -q "185.220.101.5" && ok "http scanner IP banned in nftables" || bad "http IP not banned"
nft list set inet edge_guardian blocklist4 | grep -q "45.13.22.7" && ok "honeypot IP banned in nftables" || bad "honeypot IP not banned"
grep -q "detector=honeypot" /run/t/d.log && ok "daemon logged honeypot detection" || bad "no honeypot log"

kill -TERM $PID 2>/dev/null || true; wait $PID 2>/dev/null || true
echo
echo "==================== IMAGE: $pass passed, $fail failed ===================="
[ "$fail" -eq 0 ]
'
