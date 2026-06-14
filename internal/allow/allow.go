// Package allow triển khai allowlist CIDR — tuyến phòng vệ chống tự khóa mình ra ngoài.
package allow

import (
	"net/netip"
)

// List là danh sách prefix bất biến; kiểm tra một IP có được miễn ban không.
type List struct {
	prefixes []netip.Prefix
}

// New tạo allowlist từ các prefix đã parse.
func New(prefixes []netip.Prefix) *List {
	cp := make([]netip.Prefix, len(prefixes))
	copy(cp, prefixes)
	return &List{prefixes: cp}
}

// Contains trả về true nếu addr nằm trong bất kỳ prefix nào.
// addr không hợp lệ được coi là KHÔNG nằm trong allowlist (caller tự xử lý).
func (l *List) Contains(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	for _, p := range l.prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ContainsString tiện ích: parse chuỗi IP rồi kiểm tra.
// Trả về (false, false) nếu chuỗi không phải IP hợp lệ.
func (l *List) ContainsString(ip string) (allowed bool, valid bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false, false
	}
	return l.Contains(addr), true
}
