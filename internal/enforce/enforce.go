// Package enforce thực thi ban ở tầng kernel bằng nftables named set có timeout.
//
// Thao tác nftables là Linux-only (native netlink). Triển khai thật nằm trong
// nft_linux.go (build tag linux); nft_other.go cung cấp stub để toàn bộ module vẫn
// build/test được trên các OS khác (macOS dev). Interface và config nằm ở đây để
// độc lập nền tảng.
package enforce

import (
	"net/netip"
	"time"
)

// Config tham số nftables, lấy từ block [ban] của file cấu hình.
type Config struct {
	Table      string
	SetV4      string
	SetV6      string
	BlockSetV4 string // interval set cho blocklist công khai import (CIDR)
	BlockSetV6 string
}

// Enforcer thêm/xóa IP khỏi blocklist nftables.
type Enforcer interface {
	// Ban thêm ip vào set tương ứng (v4/v6) kèm timeout còn lại.
	Ban(ip netip.Addr, timeout time.Duration) error
	// Unban xóa ip khỏi set. Không tồn tại không phải lỗi.
	Unban(ip netip.Addr) error
	// ReplaceBlockset thay toàn bộ nội dung interval set blocklist import bằng các
	// prefix cho trước (flush + nạp lại). Dùng cho import blocklist công khai định kỳ.
	ReplaceBlockset(v4, v6 []netip.Prefix) error
	// Close giải phóng kết nối netlink.
	Close() error
}

// New trả về Enforcer phù hợp nền tảng (nftables thật trên Linux, stub nơi khác).
func New(cfg Config) (Enforcer, error) {
	return newPlatform(cfg)
}
