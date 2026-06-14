// Package blocklist tải và phân tích các blocklist IP công khai (FireHOL, Spamhaus
// DROP...) thành danh sách prefix, để nạp PROACTIVELY vào nftables — chặn nguồn xấu
// đã biết trước cả khi chúng chạm tới server.
package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
)

// Set là kết quả gộp nhiều blocklist, đã tách theo họ địa chỉ và loại trùng.
type Set struct {
	V4 []netip.Prefix
	V6 []netip.Prefix
}

// Len trả tổng số prefix.
func (s Set) Len() int { return len(s.V4) + len(s.V6) }

// parseLine trích một prefix từ một dòng blocklist. Hỗ trợ:
//   - FireHOL netset: "1.2.3.0/24" hoặc "1.2.3.4" mỗi dòng, comment "#".
//   - Spamhaus DROP: "1.2.3.0/24 ; SBL123" (CIDR rồi "; mô tả").
//
// Dòng rỗng/comment ("#" hoặc ";") → bỏ. IP trần → /32 (v4) hoặc /128 (v6).
func parseLine(line string) (netip.Prefix, bool) {
	line = strings.TrimSpace(line)
	if line == "" || line[0] == '#' || line[0] == ';' {
		return netip.Prefix{}, false
	}
	// Lấy token đầu (trước khoảng trắng hoặc ";").
	tok := line
	if i := strings.IndexAny(tok, " \t;"); i >= 0 {
		tok = tok[:i]
	}
	if p, err := netip.ParsePrefix(tok); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(tok); err == nil {
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// Parse đọc một blocklist (text) thành danh sách prefix.
func Parse(r io.Reader) []netip.Prefix {
	var out []netip.Prefix
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		if p, ok := parseLine(sc.Text()); ok {
			out = append(out, p)
		}
	}
	return out
}

// Fetch tải một URL và phân tích thành prefix.
func Fetch(ctx context.Context, client *http.Client, url string) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request %q: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %q: status %d", url, resp.StatusCode)
	}
	// Giới hạn 32MB phòng nguồn độc/hỏng.
	return Parse(io.LimitReader(resp.Body, 32<<20)), nil
}

// excluder cho biết một prefix có nằm trong allowlist không (để KHÔNG chặn).
type excluder interface {
	Contains(netip.Addr) bool
}

// FetchAll tải tất cả nguồn, gộp, loại trùng, loại bỏ prefix có địa chỉ mạng nằm
// trong allowlist, rồi tách v4/v6. Một nguồn lỗi được bỏ qua (trả kèm danh sách lỗi)
// để các nguồn khác vẫn dùng được.
func FetchAll(ctx context.Context, client *http.Client, urls []string, allow excluder) (Set, []error) {
	seen := make(map[netip.Prefix]struct{})
	var set Set
	var errs []error

	for _, url := range urls {
		prefixes, err := Fetch(ctx, client, url)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, p := range prefixes {
			if _, dup := seen[p]; dup {
				continue
			}
			if allow != nil && allow.Contains(p.Addr()) {
				continue // đừng chặn dải đã allowlist
			}
			seen[p] = struct{}{}
			if p.Addr().Is4() {
				set.V4 = append(set.V4, p)
			} else {
				set.V6 = append(set.V6, p)
			}
		}
	}
	sortPrefixes(set.V4)
	sortPrefixes(set.V6)
	return set, errs
}

func sortPrefixes(ps []netip.Prefix) {
	sort.Slice(ps, func(i, j int) bool {
		if c := ps[i].Addr().Compare(ps[j].Addr()); c != 0 {
			return c < 0
		}
		return ps[i].Bits() < ps[j].Bits()
	})
}
