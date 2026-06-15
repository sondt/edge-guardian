#!/usr/bin/env bash
# Khởi tạo bảng nftables cho edge-guardian. Chạy 1 lần (idempotent) với quyền root.
# Sau khi chạy, mọi IP nằm trong set blocklist4/blocklist6 sẽ bị DROP.
#
# TÙY CHỌN (opt-in qua biến môi trường) — phát hiện port scan / honeypot bằng nft LOG:
#   EG_SERVICE_PORTS   các port DỊCH VỤ THẬT, cách nhau dấu phẩy (vd "22,80,443").
#                       Bắt buộc khai khi bật portscan/honeypot để KHÔNG tự khóa mình.
#   EG_HONEYPOT_PORTS  các port MỒI (vd "23,2323,3389"). Chạm vào = log EDGEGUARD-HONEYPOT.
#   EG_PORTSCAN=1      bật catch-all: gói NEW tới port NGOÀI service/honeypot → log
#                       EDGEGUARD-SCAN (rate-limited) rồi drop. edge-guardian đếm distinct port.
#
# nft LOG ghi vào kernel log; route sang một file cho edge-guardian tail, vd rsyslog:
#   :msg, contains, "EDGEGUARD-" -/var/log/edge-guardian/netfilter.log
# rồi trỏ honeypot.paths / portscan.paths tới file đó.
set -euo pipefail

TABLE="edge_guardian"

# Tạo table nếu chưa có.
nft list table inet "$TABLE" >/dev/null 2>&1 || nft add table inet "$TABLE"

# Set IPv4 và IPv6 với flag timeout (IP tự hết hạn theo thời gian ban).
nft list set inet "$TABLE" blocklist4 >/dev/null 2>&1 || \
    nft add set inet "$TABLE" blocklist4 '{ type ipv4_addr; flags timeout; }'
nft list set inet "$TABLE" blocklist6 >/dev/null 2>&1 || \
    nft add set inet "$TABLE" blocklist6 '{ type ipv6_addr; flags timeout; }'

# Interval set cho blocklist công khai import (CIDR). flags interval để chứa dải;
# auto-merge để nftables tự gộp các dải chồng lấp/kề nhau (FireHOL level1 đã bao gồm
# sẵn nhiều dải của Spamhaus DROP) thay vì báo "conflicting intervals".
nft list set inet "$TABLE" blockset4 >/dev/null 2>&1 || \
    nft add set inet "$TABLE" blockset4 '{ type ipv4_addr; flags interval; auto-merge; }'
nft list set inet "$TABLE" blockset6 >/dev/null 2>&1 || \
    nft add set inet "$TABLE" blockset6 '{ type ipv6_addr; flags interval; auto-merge; }'

# Chain input, priority -10 để chạy TRƯỚC các chain filter khác.
# policy accept để không ảnh hưởng traffic ngoài blocklist.
nft list chain inet "$TABLE" input >/dev/null 2>&1 || \
    nft add chain inet "$TABLE" input '{ type filter hook input priority -10; policy accept; }'

# Flush rồi add lại để tránh rule trùng lặp khi chạy nhiều lần.
nft flush chain inet "$TABLE" input

# 0) AN TOÀN BẮT BUỘC — LUÔN accept loopback + kết nối đã thiết lập TRƯỚC mọi rule drop.
#    Thiếu bước này, một dải bị chặn trùng loopback/LAN, hoặc traffic TRẢ VỀ của chính
#    host (vd nginx → 127.0.0.1 upstream, hay kết nối ra ngoài rồi nhận phản hồi), sẽ bị
#    blackhole → 504 toàn bộ site. Đây là thứ tự stateful firewall chuẩn. Đánh đổi: ban
#    chỉ chặn kết nối MỚI từ IP xấu (kết nối đang mở của nó vẫn chạy tới khi đóng) —
#    chấp nhận được, và là cách fail2ban/đa số firewall hoạt động.
nft add rule inet "$TABLE" input iif lo accept
nft add rule inet "$TABLE" input ct state established,related accept

# 1) IP đang bị ban (động) hoặc thuộc blocklist công khai (import) → drop gói MỚI trên
#    MỌI port (đặt trước các rule accept service bên dưới).
nft add rule inet "$TABLE" input ip saddr @blocklist4 drop
nft add rule inet "$TABLE" input ip6 saddr @blocklist6 drop
nft add rule inet "$TABLE" input ip saddr @blockset4 drop
nft add rule inet "$TABLE" input ip6 saddr @blockset6 drop

# 2) Phát hiện honeypot / port scan (tùy chọn). loopback + established đã accept ở (0).
if [[ -n "${EG_HONEYPOT_PORTS:-}" || "${EG_PORTSCAN:-}" == "1" ]]; then
    if [[ -n "${EG_SERVICE_PORTS:-}" ]]; then
        nft add rule inet "$TABLE" input tcp dport "{ ${EG_SERVICE_PORTS} }" accept
    fi

    # Honeypot: chạm port mồi = log + drop (edge-guardian ban ngay).
    if [[ -n "${EG_HONEYPOT_PORTS:-}" ]]; then
        nft add rule inet "$TABLE" input tcp dport "{ ${EG_HONEYPOT_PORTS} }" \
            log prefix '"EDGEGUARD-HONEYPOT "' limit rate 10/second drop
    fi

    # Port scan catch-all: gói NEW tới port còn lại → log + drop (rate-limited để không
    # ngập kernel log). CHỈ bật khi đã khai đủ EG_SERVICE_PORTS.
    if [[ "${EG_PORTSCAN:-}" == "1" ]]; then
        nft add rule inet "$TABLE" input ct state new meta l4proto tcp \
            log prefix '"EDGEGUARD-SCAN "' limit rate 10/second
        nft add rule inet "$TABLE" input ct state new meta l4proto tcp drop
    fi
fi

echo "Đã khởi tạo nftables table '$TABLE'."
echo "Xem IP đang bị chặn: nft list set inet $TABLE blocklist4"
if [[ -n "${EG_HONEYPOT_PORTS:-}" || "${EG_PORTSCAN:-}" == "1" ]]; then
    echo "Đã bật log honeypot/portscan — nhớ route 'EDGEGUARD-*' từ kernel log sang file"
    echo "cho edge-guardian tail (xem hướng dẫn đầu script + docs/03)."
fi
