#!/usr/bin/env bash
# edge-guardian uninstaller — the mirror of install.sh.
#
#   curl -fsSL https://raw.githubusercontent.com/sondt/edge-guardian/main/uninstall.sh | sudo bash
#
# Stops + disables the service (and the self-update timer), deletes the nftables table
# (which lifts EVERY active ban immediately — both dynamic bans and imported blocklists),
# removes the binaries and systemd units, and reverts the optional nginx log snippet.
# Idempotent — safe to re-run, and a no-op for anything already gone.
#
# Config and state are KEPT by default so a re-install picks up where you left off.
# Pass --purge (or EDGEGUARD_PURGE=1) to also delete /etc/edge-guardian,
# /var/lib/edge-guardian and /var/log/edge-guardian.
#
# Env overrides:
#   EDGEGUARD_PURGE     set to 1 to also remove config, state and the log dir
#   EDGEGUARD_KEEP_NFT  set to 1 to leave the nftables table in place (bans stay active)
set -euo pipefail

TABLE="edge_guardian"
ETC_DIR=/etc/edge-guardian
LIB_DIR=/var/lib/edge-guardian
LOG_DIR=/var/log/edge-guardian

PURGE="${EDGEGUARD_PURGE:-0}"
for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    *) echo "unknown argument: $arg (supported: --purge)" >&2; exit 2 ;;
  esac
done

log() { echo "==> $*"; }
die() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "must run as root (use sudo)"
[ "$(uname -s)" = "Linux" ] || die "edge-guardian runs on Linux only"

have_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

# 1) Stop + disable the service and the self-update timer/service.
if have_systemd; then
  log "Stopping and disabling services…"
  systemctl disable --now edge-guardian.service        >/dev/null 2>&1 || true
  systemctl disable --now edge-guardian-update.timer   >/dev/null 2>&1 || true
  systemctl stop          edge-guardian-update.service >/dev/null 2>&1 || true
else
  log "No systemd detected — skipping service stop."
fi

# 2) If installed from a .deb/.rpm, let the package manager own the removal of its files.
if command -v dpkg >/dev/null 2>&1 && dpkg -s edge-guardian >/dev/null 2>&1; then
  log "Detected the .deb package — removing it via apt-get."
  if [ "$PURGE" = "1" ]; then
    apt-get purge -y edge-guardian  >/dev/null 2>&1 || true
  else
    apt-get remove -y edge-guardian >/dev/null 2>&1 || true
  fi
elif command -v rpm >/dev/null 2>&1 && rpm -q edge-guardian >/dev/null 2>&1; then
  log "Detected the .rpm package — removing it via the package manager."
  { command -v dnf >/dev/null 2>&1 && dnf remove -y edge-guardian; } >/dev/null 2>&1 \
    || { command -v yum >/dev/null 2>&1 && yum remove -y edge-guardian >/dev/null 2>&1; } \
    || true
fi

# 3) Delete the nftables table — this lifts every active ban at once. Skippable.
if [ "${EDGEGUARD_KEEP_NFT:-0}" = "1" ]; then
  log "EDGEGUARD_KEEP_NFT=1 — leaving the nftables table '$TABLE' in place (bans stay active)."
elif command -v nft >/dev/null 2>&1 && nft list table inet "$TABLE" >/dev/null 2>&1; then
  log "Deleting nftables table '$TABLE' (lifts all active bans)…"
  nft delete table inet "$TABLE" || log "could not delete table '$TABLE' — remove it manually."
else
  log "No nftables table '$TABLE' to remove."
fi

# 4) Remove binaries + systemd units left by the one-line installer (the package manager
#    already handled its own copies above; rm is a no-op when they are gone).
log "Removing binaries and systemd units…"
rm -f /usr/local/bin/edge-guardian
rm -f /usr/local/bin/edge-guardian-update
rm -f /etc/systemd/system/edge-guardian.service
rm -f /etc/systemd/system/edge-guardian-update.service
rm -f /etc/systemd/system/edge-guardian-update.timer
have_systemd && systemctl daemon-reload >/dev/null 2>&1 || true

# 5) Revert the optional nginx log snippet the installer may have added, then reload nginx.
#    Vhosts that reference the eg_guardian log_format directly must be edited by hand —
#    we never touch existing vhost config.
nginx_snippet_removed=0
for snip in /etc/nginx/conf.d/00-edge-guardian-log.conf /etc/nginx/conf.d/edge-guardian-log.conf; do
  if [ -f "$snip" ]; then
    rm -f "$snip"
    nginx_snippet_removed=1
    log "Removed nginx log snippet: $snip"
  fi
done
if [ "$nginx_snippet_removed" = "1" ] && command -v nginx >/dev/null 2>&1; then
  if nginx -t >/dev/null 2>&1; then
    nginx -s reload 2>/dev/null || systemctl reload nginx 2>/dev/null || true
    log "Reloaded nginx."
  else
    log "WARNING: 'nginx -t' failed — a vhost may still reference the eg_guardian log_format."
    log "         Remove any 'access_log .../edge-guardian/access.log eg_guardian;' lines, then reload nginx."
  fi
fi

# 6) Config, state and logs — kept unless --purge.
if [ "$PURGE" = "1" ]; then
  log "Purging config, state and logs…"
  rm -rf "$ETC_DIR" "$LIB_DIR" "$LOG_DIR"
else
  log "Keeping config ($ETC_DIR) and state ($LIB_DIR). Pass --purge to remove them."
fi

echo
log "Done. edge-guardian has been removed."
if [ "$PURGE" != "1" ]; then
  echo "   Left in place: $ETC_DIR, $LIB_DIR"
  echo "   Remove them too with: curl -fsSL .../uninstall.sh | sudo bash -s -- --purge"
fi
