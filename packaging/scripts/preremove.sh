#!/bin/sh
# edge-guardian preremove — runs before removal. On upgrade (rpm: $1>=1, deb: "upgrade")
# we keep the service running; only stop on true removal.
set -e

is_upgrade=0
# rpm passes the number of remaining versions as $1 (>=1 means upgrade).
case "${1:-}" in
    1|2|3|4|5|6|7|8|9) is_upgrade=1 ;;
esac
# deb passes "upgrade"/"remove"/"purge".
case "${1:-}" in
    upgrade|failed-upgrade) is_upgrade=1 ;;
esac

if [ "$is_upgrade" -eq 0 ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now edge-guardian.service >/dev/null 2>&1 || true
fi

exit 0
