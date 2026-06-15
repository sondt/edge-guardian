#!/usr/bin/env bash
# edge-guardian one-line installer.
#
#   curl -fsSL https://raw.githubusercontent.com/sondt/edge-guardian/main/install.sh | sudo bash
#
# Detects arch, installs the static binary, writes a starter config + systemd unit,
# initializes the nftables table, and enables the service. Idempotent — safe to re-run.
#
# Env overrides:
#   EDGEGUARD_VERSION   release tag to install (default: latest)
#   EDGEGUARD_REPO      GitHub repo (default: sondt/edge-guardian)
#   EDGEGUARD_BINARY    path to a local binary to install instead of downloading (for testing)
#   EDGEGUARD_NO_START  set to 1 to skip enabling/starting the service
set -euo pipefail

REPO="${EDGEGUARD_REPO:-sondt/edge-guardian}"
VERSION="${EDGEGUARD_VERSION:-latest}"
BIN_DIR=/usr/local/bin
ETC_DIR=/etc/edge-guardian
LIB_DIR=/var/lib/edge-guardian
CONFIG="$ETC_DIR/config.toml"
UNIT=/etc/systemd/system/edge-guardian.service

log()  { echo "==> $*"; }
die()  { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
[ "$(uname -s)" = "Linux" ] || die "edge-guardian runs on Linux only"
command -v nft >/dev/null 2>&1 || die "nftables ('nft') not found — install it first (apt install nftables / dnf install nftables)"

# Detect arch.
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  aarch64|arm64) ARCH=arm64 ;;
  *) die "unsupported architecture: $(uname -m)" ;;
esac

log "Installing edge-guardian ($ARCH)…"

# fetch <url> <dest> — download with curl or wget, retrying transient failures
# (GitHub's CDN occasionally returns a 504/503 on release-asset downloads).
fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 5 --retry-delay 2 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget --tries=5 --waitretry=2 -qO "$2" "$1"
  else
    die "need curl or wget to download"
  fi
}

# EG_LOG_PATH / EG_LINE_REGEX feed the generated [log] config. Default: nginx's standard
# combined log with no $host (every request folds into one "all" site).
EG_LOG_PATH="/var/log/nginx/access.log"
EG_LINE_REGEX=""

# configure_nginx_logging optionally adds a dedicated nginx access log carrying $host so
# Edge Guardian can break stats down per domain. It NEVER edits existing config — it only
# drops a self-contained snippet, validates with `nginx -t`, reloads, and rolls back on
# failure. Interactive: it reads /dev/tty (works even under `curl | bash`, where stdin is
# the script). Skipped silently when there is no terminal (cron/CI) or no nginx.
configure_nginx_logging() {
  command -v nginx >/dev/null 2>&1 || return 0
  if [ ! -r /dev/tty ]; then
    log "Non-interactive install — skipping nginx \$host log setup (see config comments)."
    return 0
  fi

  local snip="/etc/nginx/conf.d/edge-guardian-log.conf"
  if nginx -T 2>/dev/null | grep -qiE 'log_format[^;]*\$host'; then
    log "nginx already logs \$host — per-site stats can use your current access log."
  fi

  printf '\n  Edge Guardian can add a dedicated nginx access log carrying $host for\n' > /dev/tty
  printf '  per-site health/error stats. It is a separate snippet — your existing\n' > /dev/tty
  printf '  nginx config is left untouched, and reverted automatically if invalid.\n' > /dev/tty
  printf '  Add it now? [t]ext / [j]son / [s]kip (default s): ' > /dev/tty
  local ans=""
  read -r ans < /dev/tty || ans="s"

  local fmt
  case "$ans" in
    t|T|text|TEXT) fmt="text" ;;
    j|J|json|JSON) fmt="json" ;;
    *) log "Skipped nginx log setup."; return 0 ;;
  esac

  mkdir -p /var/log/edge-guardian
  if [ "$fmt" = "json" ]; then
    cat > "$snip" <<'NG'
# Added by the edge-guardian installer. A dedicated access log carrying $host for
# per-site stats. Safe to remove; does not affect your other access logs.
log_format eg_guardian escape=json '{"host":"$host","remote_addr":"$remote_addr","uri":"$request_uri","status":$status,"request_time":$request_time,"bytes":$body_bytes_sent,"ua":"$http_user_agent","upstream_status":"$upstream_status"}';
access_log /var/log/edge-guardian/access.log eg_guardian;
NG
  else
    cat > "$snip" <<'NG'
# Added by the edge-guardian installer. A dedicated access log carrying $host for
# per-site stats. Safe to remove; does not affect your other access logs.
log_format eg_guardian '$host $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"';
access_log /var/log/edge-guardian/access.log eg_guardian;
NG
  fi

  if ! nginx -t >/dev/null 2>&1; then
    rm -f "$snip"
    log "nginx -t failed — reverted the snippet, nothing changed. Configure logging manually."
    return 0
  fi
  nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true

  EG_LOG_PATH="/var/log/edge-guardian/access.log"
  if [ "$fmt" = "text" ]; then
    EG_LINE_REGEX='^(?P<host>\S+) (?P<ip>\S+) \S+ \S+ \[[^\]]+\] "(?:\S+) (?P<uri>\S+)[^"]*" (?P<status>\d+) (?P<bytes>\S+) "[^"]*" "(?P<ua>[^"]*)"'
  fi
  log "Added nginx access log ($fmt): /var/log/edge-guardian/access.log"
  log "NOTE: vhosts that declare their own 'access_log' won't inherit this. Add to each:"
  log "      access_log /var/log/edge-guardian/access.log eg_guardian;"
}

# 1) Binary. Release assets are GoReleaser tarballs named
#    edge-guardian_<version>_linux_<arch>.tar.gz with the binary at the archive root.
if [ -n "${EDGEGUARD_BINARY:-}" ]; then
  log "Using local binary: $EDGEGUARD_BINARY"
  install -m 0755 "$EDGEGUARD_BINARY" "$BIN_DIR/edge-guardian"
else
  # Resolve the release tag (e.g. v0.2.0). "latest" → ask the GitHub API.
  if [ "$VERSION" = "latest" ]; then
    api="$(mktemp)"
    fetch "https://api.github.com/repos/$REPO/releases/latest" "$api" \
      || die "could not query the latest release"
    TAG="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$api" | head -n1)"
    rm -f "$api"
    [ -n "$TAG" ] || die "could not resolve the latest release tag"
  else
    TAG="$VERSION"
  fi
  VER="${TAG#v}"   # GoReleaser asset names drop the leading 'v'
  ASSET="edge-guardian_${VER}_linux_${ARCH}.tar.gz"
  URL="https://github.com/$REPO/releases/download/$TAG/$ASSET"

  log "Downloading $URL"
  tmpd="$(mktemp -d)"
  fetch "$URL" "$tmpd/eg.tar.gz" || die "download failed ($URL)"
  tar -xzf "$tmpd/eg.tar.gz" -C "$tmpd" edge-guardian \
    || die "archive did not contain the edge-guardian binary"
  install -m 0755 "$tmpd/edge-guardian" "$BIN_DIR/edge-guardian"
  rm -rf "$tmpd"
fi
"$BIN_DIR/edge-guardian" --version || die "installed binary does not run"

# 2) Directories.
mkdir -p "$ETC_DIR" "$LIB_DIR"

# 3) nginx logging (interactive, optional) then the starter config.
configure_nginx_logging

if [ ! -f "$CONFIG" ]; then
  log "Writing starter config: $CONFIG"
  {
    printf '# edge-guardian config — edit, then: systemctl restart edge-guardian\n'
    printf '[log]\n'
    printf 'paths = ["%s"]\n' "$EG_LOG_PATH"
    if [ -n "$EG_LINE_REGEX" ]; then
      printf "line_regex = '%s'\n" "$EG_LINE_REGEX"
    fi
    cat <<'TOML'
# Per-site health/errors need the request's $host. nginx's default "combined" format
# does NOT log it, so every request folds into one "all" site. Re-run the installer to
# add a $host access log automatically, or add one manually and set a matching line_regex.
# (Edge Guardian still lists every domain from `nginx -T` even without this.)

[detection]
bad_uri_patterns = [
  '\.(php|cgi|asp|aspx|jsp|env|git|sql|bak)(\?|/|$)',
  '/(wp-admin|wp-login|wp-content|xmlrpc)',
  '/(phpmyadmin|pma|adminer)',
  '/(\.env|\.git|\.aws|\.ssh)',
]
threshold = 1
window_secs = 60
dry_run = true   # start safe: detect + alert, do NOT block. Flip to false once happy.

[ban]
duration = "168h"
whitelist = ["127.0.0.0/8", "::1/128"]
nft_table = "edge_guardian"
nft_set_v4 = "blocklist4"
nft_set_v6 = "blocklist6"

[telegram]
enabled = false

[email]
enabled = false

[sshd]
enabled = false

[state]
path = "/var/lib/edge-guardian/state.json"
TOML
  } > "$CONFIG"
  chmod 600 "$CONFIG"
else
  log "Config exists, keeping it: $CONFIG"
  # If the user just opted into a $host access log, point the EXISTING config at it —
  # otherwise Edge Guardian keeps reading the old host-less log and every request folds
  # into "all". A timestamped backup is written first. paths uses '#' as the sed
  # delimiter (the path has slashes); line_regex is inserted verbatim via sed's `r` so
  # its backslashes are never mangled.
  if [ "$EG_LOG_PATH" != "/var/log/nginx/access.log" ]; then
    cp -p "$CONFIG" "$CONFIG.bak" 2>/dev/null || true
    sed -i 's#^[[:space:]]*paths[[:space:]]*=.*#paths = ["'"$EG_LOG_PATH"'"]#' "$CONFIG"
    sed -i '/^[[:space:]]*line_regex[[:space:]]*=/d' "$CONFIG"
    if [ -n "$EG_LINE_REGEX" ]; then
      _lr="$(mktemp)"
      printf "line_regex = '%s'\n" "$EG_LINE_REGEX" > "$_lr"
      sed -i '/^[[:space:]]*paths[[:space:]]*=/r '"$_lr" "$CONFIG"
      rm -f "$_lr"
    fi
    log "Updated $CONFIG to read the new \$host log (backup: $CONFIG.bak)."
  fi
fi

# 4) Initialize nftables (table + sets + drop rules). Idempotent.
#    MUST mirror setup-nftables.sh: blockset uses auto-merge (overlapping public-list
#    ranges), and the input chain ALWAYS accepts loopback + established connections
#    BEFORE any drop — without that, a blocked range overlapping loopback/LAN (or the
#    host's own return traffic) is blackholed → 504 on every site.
log "Initializing nftables table 'edge_guardian'…"
nft list table inet edge_guardian >/dev/null 2>&1 || nft add table inet edge_guardian
nft list set inet edge_guardian blocklist4 >/dev/null 2>&1 || nft add set inet edge_guardian blocklist4 '{ type ipv4_addr; flags timeout; }'
nft list set inet edge_guardian blocklist6 >/dev/null 2>&1 || nft add set inet edge_guardian blocklist6 '{ type ipv6_addr; flags timeout; }'
nft list set inet edge_guardian blockset4 >/dev/null 2>&1 || nft add set inet edge_guardian blockset4 '{ type ipv4_addr; flags interval; auto-merge; }'
nft list set inet edge_guardian blockset6 >/dev/null 2>&1 || nft add set inet edge_guardian blockset6 '{ type ipv6_addr; flags interval; auto-merge; }'
nft list chain inet edge_guardian input >/dev/null 2>&1 || nft add chain inet edge_guardian input '{ type filter hook input priority -10; policy accept; }'
nft flush chain inet edge_guardian input
nft add rule inet edge_guardian input iif lo accept
nft add rule inet edge_guardian input ct state established,related accept
nft add rule inet edge_guardian input ip saddr @blocklist4 drop
nft add rule inet edge_guardian input ip6 saddr @blocklist6 drop
nft add rule inet edge_guardian input ip saddr @blockset4 drop
nft add rule inet edge_guardian input ip6 saddr @blockset6 drop

# 5) systemd unit.
log "Writing systemd unit: $UNIT"
cat > "$UNIT" <<'UNITFILE'
[Unit]
Description=edge-guardian intrusion prevention daemon
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/edge-guardian --config /etc/edge-guardian/config.toml
Restart=always
RestartSec=3
User=root
NoNewPrivileges=false
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/var/lib/edge-guardian
UMask=0077

[Install]
WantedBy=multi-user.target
UNITFILE

# 6) Enable + start (unless skipped or systemd unavailable).
if [ "${EDGEGUARD_NO_START:-}" != "1" ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  log "Enabling + (re)starting service…"
  systemctl daemon-reload
  systemctl enable edge-guardian >/dev/null 2>&1 || true
  # restart (not just enable --now) so a re-run picks up the new binary AND any config
  # change made above; restart also starts the service if it was stopped.
  systemctl restart edge-guardian
  systemctl --no-pager status edge-guardian | head -5 || true
else
  log "Skipping service start (no systemd or EDGEGUARD_NO_START=1)."
fi

echo
log "Done. edge-guardian installed."
echo "   Config : $CONFIG  (currently dry_run = true — safe to observe first)"
echo "   Logs   : journalctl -u edge-guardian -f"
echo "   Edit the config (set log paths, Telegram/email, whitelist), then:"
echo "     sudo \$EDITOR $CONFIG  &&  sudo systemctl restart edge-guardian"
echo "   Flip detection.dry_run = false when you're ready to actually block."
