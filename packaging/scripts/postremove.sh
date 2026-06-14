#!/bin/sh
# edge-guardian postremove — reload systemd after the unit file is gone (true removal only).
set -e

is_upgrade=0
case "${1:-}" in
    1|2|3|4|5|6|7|8|9) is_upgrade=1 ;;
    upgrade|failed-upgrade) is_upgrade=1 ;;
esac

if [ "$is_upgrade" -eq 0 ] && command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

# Note: we deliberately leave the nftables table and /var/lib/edge-guardian in place so a
# reinstall keeps the ban list. To fully clean up:
#   sudo nft delete table inet edge_guardian ; sudo rm -rf /var/lib/edge-guardian
exit 0
