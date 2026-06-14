#!/usr/bin/env bash
# Runs INSIDE the privileged debian container (see dev/docker-test.sh).
set -euo pipefail

pass=0; fail=0
ok()   { echo "  ✓ $1"; pass=$((pass+1)); }
bad()  { echo "  ✗ $1"; fail=$((fail+1)); }

echo "==> installing nftables + tools"
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq nftables iproute2 netcat-openbsd procps python3-minimal >/dev/null 2>&1

BIN=/repo/dist/edge-guardian-linux-amd64
RUN=/tmp/nsg; mkdir -p "$RUN"
NFLOG="$RUN/netfilter.log"; : > "$NFLOG"

echo "==> setup-nftables.sh (with honeypot :2323 + portscan, services 22,80,443)"
EG_SERVICE_PORTS="22,80,443" EG_HONEYPOT_PORTS="2323" EG_PORTSCAN=1 \
  bash /repo/setup-nftables.sh >/dev/null

# Assertions below may legitimately have grep return non-zero; don't let set -e abort.
set +e

CHAIN="$(nft list chain inet edge_guardian input 2>/dev/null)"
nft list table inet edge_guardian >/dev/null 2>&1 && ok "edge_guardian table created" || bad "table missing"
echo "$CHAIN" | grep -q 'EDGEGUARD-HONEYPOT' && ok "honeypot log rule present" || { bad "honeypot rule missing"; echo "$CHAIN" | sed 's/^/      /'; }
echo "$CHAIN" | grep -q 'EDGEGUARD-SCAN' && ok "portscan log rule present" || bad "portscan rule missing"

echo "==> safety rules present (loopback + established accepted before honeypot/scan)"
echo "$CHAIN" | grep -q 'iif "lo" accept' && ok "loopback accepted before detection rules" || bad "missing loopback-accept safety rule"
echo "$CHAIN" | grep -q 'ct state established,related accept' && ok "established/related accepted" || bad "missing established-accept rule"
echo "$CHAIN" | grep -q 'tcp dport { 22, 80, 443 } accept' && ok "service ports accepted (no false scan)" || bad "service ports not accepted"

echo "==> serve a public-blocklist sample over HTTP for the importer"
mkdir -p "$RUN/www"
printf '# sample\n203.0.113.0/24\n198.51.100.7\n10.0.0.0/8\n' > "$RUN/www/list.txt"
( cd "$RUN/www" && python3 -m http.server 8099 >/dev/null 2>&1 ) &
HTTPD=$!
sleep 1

echo "==> config: REAL mode (dry_run=false) — honeypot + portscan + blocklist import"
cat > "$RUN/config.toml" <<EOF
[log]
paths = ["$RUN/access.log"]
[detection]
bad_uri_patterns = ['\\.php(\\?|/|\$)']
threshold = 1
window_secs = 60
dry_run = false
[ban]
duration = "24h"
whitelist = ["127.0.0.0/8","::1/128","10.0.0.0/8"]
nft_table = "edge_guardian"
nft_set_v4 = "blocklist4"
nft_set_v6 = "blocklist6"
[telegram]
enabled = false
[honeypot]
enabled = true
paths = ["$NFLOG"]
log_prefix = "EDGEGUARD-HONEYPOT"
[portscan]
enabled = true
paths = ["$NFLOG"]
log_prefix = "EDGEGUARD-SCAN"
threshold = 5
window_secs = 60
[blocklist]
enabled = true
sources = ["http://127.0.0.1:8099/list.txt"]
refresh_hours = 24
[state]
path = "$RUN/state.json"
[control]
enabled = true
socket_path = "$RUN/ns.sock"
EOF
: > "$RUN/access.log"

"$BIN" -c "$RUN/config.toml" >"$RUN/daemon.log" 2>&1 &
PID=$!
sleep 1

echo "==> honeypot: one netfilter LOG line → instant REAL ban in nftables set"
echo 'host kernel: EDGEGUARD-HONEYPOT IN=eth0 SRC=45.13.22.7 DST=10.0.0.1 PROTO=TCP SPT=5 DPT=2323 SYN' >> "$NFLOG"
sleep 1
nft list set inet edge_guardian blocklist4 | grep -q '45.13.22.7' && ok "honeypot IP banned in real nftables set" || bad "honeypot IP NOT in nftables set"

echo "==> portscan: 5 distinct ports from one IP → REAL ban; repeats don't count"
for p in 22 22 22 22; do echo "host kernel: EDGEGUARD-SCAN SRC=185.220.101.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=$p SYN" >> "$NFLOG"; done
sleep 0.6
nft list set inet edge_guardian blocklist4 | grep -q '185.220.101.5' && bad "banned on repeated SAME port (should not)" || ok "repeated same port did not ban"
for p in 23 80 443 3306 8080; do echo "host kernel: EDGEGUARD-SCAN SRC=185.220.101.5 DST=10.0.0.1 PROTO=TCP SPT=1 DPT=$p SYN" >> "$NFLOG"; done
sleep 1
nft list set inet edge_guardian blocklist4 | grep -q '185.220.101.5' && ok "port-scan IP banned after 5 distinct ports" || bad "port-scan IP NOT banned"

echo "==> unban via control socket removes the IP from the live nftables set"
"$BIN" -c "$RUN/config.toml" unban 45.13.22.7 >/dev/null 2>&1
sleep 0.3
nft list set inet edge_guardian blocklist4 | grep -q '45.13.22.7' && bad "unban left IP in set" || ok "unban removed IP from nftables set"

echo "==> ban persists in state.json (survives restart)"
grep -q '185.220.101.5' "$RUN/state.json" && ok "ban recorded in state.json" || bad "ban not in state"

echo "==> public blocklist imported into nftables interval set (blockset4)"
BS="$(nft list set inet edge_guardian blockset4 2>/dev/null)"
echo "$BS" | grep -q '203.0.113.0/24' && ok "blocklist CIDR 203.0.113.0/24 in blockset4" || bad "CIDR not imported"
echo "$BS" | grep -q '198.51.100.7' && ok "blocklist host 198.51.100.7 in blockset4" || bad "host not imported"
echo "$BS" | grep -q '10.0.0.0/8' && bad "allowlisted 10.0.0.0/8 should be EXCLUDED" || ok "allowlisted range excluded from import"

kill $HTTPD 2>/dev/null || true
kill -TERM $PID 2>/dev/null || true; wait $PID 2>/dev/null || true

echo
echo "==> daemon log (ban events):"
grep -iE 'banned|detector=' "$RUN/daemon.log" | head -6 | sed 's/^/    /'
echo
echo "==================== RESULT: $pass passed, $fail failed ===================="
[ "$fail" -eq 0 ]
