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

# fetch <url> <dest> — download with curl or wget.
fetch() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    die "need curl or wget to download"
  fi
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

# 3) Starter config (only if absent — never clobber an edited config).
if [ ! -f "$CONFIG" ]; then
  log "Writing starter config: $CONFIG"
  cat > "$CONFIG" <<'TOML'
# edge-guardian config — edit, then: systemctl restart edge-guardian
[log]
paths = ["/var/log/nginx/access.log"]

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
  chmod 600 "$CONFIG"
else
  log "Config exists, keeping it: $CONFIG"
fi

# 4) Initialize nftables (table + sets + drop rules). Idempotent.
log "Initializing nftables table 'edge_guardian'…"
nft list table inet edge_guardian >/dev/null 2>&1 || nft add table inet edge_guardian
nft list set inet edge_guardian blocklist4 >/dev/null 2>&1 || nft add set inet edge_guardian blocklist4 '{ type ipv4_addr; flags timeout; }'
nft list set inet edge_guardian blocklist6 >/dev/null 2>&1 || nft add set inet edge_guardian blocklist6 '{ type ipv6_addr; flags timeout; }'
nft list set inet edge_guardian blockset4 >/dev/null 2>&1 || nft add set inet edge_guardian blockset4 '{ type ipv4_addr; flags interval; }'
nft list set inet edge_guardian blockset6 >/dev/null 2>&1 || nft add set inet edge_guardian blockset6 '{ type ipv6_addr; flags interval; }'
nft list chain inet edge_guardian input >/dev/null 2>&1 || nft add chain inet edge_guardian input '{ type filter hook input priority -10; policy accept; }'
nft flush chain inet edge_guardian input
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
  log "Enabling + starting service…"
  systemctl daemon-reload
  systemctl enable --now edge-guardian
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
