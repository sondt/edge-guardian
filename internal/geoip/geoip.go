// Package geoip giải IP nguồn (của attacker) thành thông tin vị trí (quốc gia/tỉnh/
// thành) và mạng (ASN/ISP) HOÀN TOÀN OFFLINE từ file MMDB (định dạng MaxMind), để làm
// giàu thông báo ban và dashboard. KHÔNG gọi API địa lý ngoài.
//
// Nguồn dữ liệu khuyến nghị: bộ City + ASN MMDB miễn phí, giấy phép CC của
// "sapics/ip-location-db" (tương thích định dạng MaxMind). Bộ City của sapics CHỈ phát
// hành tách rời IPv4 và IPv6 (không có file gộp), nên mỗi tham số đường dẫn nhận DANH
// SÁCH file ngăn cách bằng dấu phẩy — ví dụ trỏ cả
// "dbip-city-ipv4.mmdb,dbip-city-ipv6.mmdb" để phủ cả hai họ địa chỉ. Lookup tra lần
// lượt từng reader tới khi có file chứa IP đó.
//
// Resolver luôn AN TOÀN khi suy biến: thiếu file / đường dẫn rỗng / file hỏng → no-op
// trả Result rỗng. Lookup KHÔNG bao giờ trả lỗi và nil-safe.
package geoip

import (
	"fmt"
	"net"
	"strings"

	maxminddb "github.com/oschwald/maxminddb-golang"
)

// LƯU Ý KỸ THUẬT: dùng maxminddb-golang ĐỌC TRỰC TIẾP thay vì geoip2-golang. Lý do:
// file mmdb của sapics/ip-location-db đặt metadata `database_type` phi chuẩn ("city ipv4",
// "asn ipv4") khiến geoip2-golang chặn ở method .City()/.ASN() ("reader does not support
// the X database type") DÙ dữ liệu bên trong vẫn theo schema MaxMind. Đọc thẳng bằng
// maxminddb.Lookup vào struct schema-MaxMind bỏ qua được guard đó → chạy với CẢ file sapics
// LẪN file MaxMind/DB-IP chuẩn.

// mmCity là phần schema MaxMind/DB-IP LỒNG cần lấy từ City DB.
type mmCity struct {
	Country struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Subdivisions []struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"subdivisions"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
	Traits struct {
		IsAnonymousProxy bool `maxminddb:"is_anonymous_proxy"`
		IsAnycast        bool `maxminddb:"is_anycast"`
	} `maxminddb:"traits"`
}

// mmCityFlat là schema PHẲNG của sapics/ip-location-db dbip-city (country_code/city/
// state1/…). Khác hẳn schema LỒNG của MaxMind — file sapics dùng cái này.
type mmCityFlat struct {
	CountryCode string  `maxminddb:"country_code"` // mã ISO (vd "VN","US")
	City        string  `maxminddb:"city"`
	State1      string  `maxminddb:"state1"` // tỉnh/bang
	State2      string  `maxminddb:"state2"` // quận/huyện (nếu có)
	Latitude    float64 `maxminddb:"latitude"`
	Longitude   float64 `maxminddb:"longitude"`
}

// mmASN là phần schema cần lấy từ ASN DB.
type mmASN struct {
	AutonomousSystemNumber       uint   `maxminddb:"autonomous_system_number"`
	AutonomousSystemOrganization string `maxminddb:"autonomous_system_organization"`
}

// Result là thông tin giải được cho một IP. Trường rỗng = không xác định.
// IsInternal=true cho IP nội bộ (private/loopback/link-local) — không tra DB.
type Result struct {
	Country    string  // tên quốc gia (ưu tiên) hoặc mã ISO. Vd "Việt Nam" / "VN".
	Region     string  // tỉnh/thành (subdivision).
	City       string  // thành phố/quận.
	Lat        float64 // vĩ độ xấp xỉ mức thành phố.
	Lon        float64 // kinh độ xấp xỉ mức thành phố.
	ASN        int     // số hệ thống tự trị. 0 = không xác định.
	Org        string  // tên ISP/tổ chức. Vd "Viettel Group".
	IsHosting  bool    // cờ datacenter/hosting/VPN (best-effort) — attacker hay đến từ đây.
	IsInternal bool    // IP nội bộ (private/loopback/link-local).
}

// ASNLabel định dạng ASN + tổ chức thành nhãn ngắn: "AS24940 Hetzner" / "AS24940" /
// "Hetzner" / "" (không xác định).
func (r Result) ASNLabel() string {
	switch {
	case r.ASN != 0 && r.Org != "":
		return fmt.Sprintf("AS%d %s", r.ASN, r.Org)
	case r.ASN != 0:
		return fmt.Sprintf("AS%d", r.ASN)
	default:
		return r.Org
	}
}

// Nop là resolver no-op (mọi Lookup trả Result rỗng). Dùng khi tắt GeoIP.
type Nop struct{}

// Lookup trên Nop luôn trả Result rỗng.
func (Nop) Lookup(string) Result { return Result{} }

// Resolver tra cứu vị trí + mạng cho một IP. Con trỏ nil = no-op (an toàn khi chưa wire).
// Mỗi loại giữ DANH SÁCH reader (để phủ file IPv4 + IPv6 tách rời).
type Resolver struct {
	city []*maxminddb.Reader
	asn  []*maxminddb.Reader
}

// splitPaths tách chuỗi đường dẫn ngăn cách bằng dấu phẩy thành danh sách đã trim,
// bỏ phần tử rỗng.
func splitPaths(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// New mở các reader MMDB. Mỗi tham số là một DANH SÁCH file ngăn cách bằng dấu phẩy
// (để phủ IPv4 + IPv6 tách rời); rỗng → bỏ qua loại tương ứng. File thiếu/không đọc
// được → trả lỗi NHƯNG giữ lại các reader đã mở (caller nên log cảnh báo rồi tiếp tục).
// Trả về *Resolver luôn KHÁC nil ngay cả khi mọi đường dẫn rỗng (no-op thuần).
func New(cityDBPaths, asnDBPaths string) (*Resolver, error) {
	r := &Resolver{}
	for _, p := range splitPaths(cityDBPaths) {
		reader, err := maxminddb.Open(p)
		if err != nil {
			return r, fmt.Errorf("open GeoIP City DB %q: %w", p, err)
		}
		r.city = append(r.city, reader)
	}
	for _, p := range splitPaths(asnDBPaths) {
		reader, err := maxminddb.Open(p)
		if err != nil {
			return r, fmt.Errorf("open GeoIP ASN DB %q: %w", p, err)
		}
		r.asn = append(r.asn, reader)
	}
	return r, nil
}

// Stats trả số reader City/ASN đã mở thành công — để log chẩn đoán lúc khởi động. nil-safe.
func (r *Resolver) Stats() (city, asn int) {
	if r == nil {
		return 0, 0
	}
	return len(r.city), len(r.asn)
}

// Close đóng mọi reader đang mở. nil-safe. Trả error để khớp interface io.Closer-style.
func (r *Resolver) Close() error {
	if r == nil {
		return nil
	}
	for _, rd := range r.city {
		_ = rd.Close()
	}
	for _, rd := range r.asn {
		_ = rd.Close()
	}
	return nil
}

// Lookup giải một IP (chuỗi) thành Result. KHÔNG bao giờ trả lỗi: IP rác → Result rỗng;
// IP nội bộ → IsInternal=true (không tra DB); thiếu reader → phần tương ứng để rỗng.
// nil-safe.
func (r *Resolver) Lookup(ipStr string) Result {
	if r == nil {
		return Result{}
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return Result{}
	}
	if isInternalIP(ip) {
		return Result{IsInternal: true}
	}
	var res Result
	r.fillCity(ip, &res)
	r.fillASN(ip, &res)
	return res
}

func (r *Resolver) fillCity(ip net.IP, res *Result) {
	for _, rd := range r.city {
		if applyCity(rd, ip, res) {
			return
		}
	}
}

// applyCity thử decode 1 reader theo CẢ HAI schema: sapics PHẲNG trước, rồi MaxMind LỒNG.
// Trả true nếu lấy được quốc gia.
func applyCity(rd *maxminddb.Reader, ip net.IP, res *Result) bool {
	var f mmCityFlat
	if err := rd.Lookup(ip, &f); err == nil && f.CountryCode != "" {
		res.Country = f.CountryCode
		res.Region = firstNonEmpty(f.State1, f.State2)
		res.City = f.City
		res.Lat = f.Latitude
		res.Lon = f.Longitude
		return true
	}
	var n mmCity
	if err := rd.Lookup(ip, &n); err == nil {
		country := pickName(n.Country.Names, n.Country.ISOCode)
		if country == "" {
			return false
		}
		res.Country = country
		if len(n.Subdivisions) > 0 {
			res.Region = pickName(n.Subdivisions[0].Names, n.Subdivisions[0].ISOCode)
		}
		res.City = pickName(n.City.Names, "")
		res.Lat = n.Location.Latitude
		res.Lon = n.Location.Longitude
		if n.Traits.IsAnonymousProxy || n.Traits.IsAnycast {
			res.IsHosting = true
		}
		return true
	}
	return false
}

func (r *Resolver) fillASN(ip net.IP, res *Result) {
	for _, rd := range r.asn {
		var a mmASN
		if err := rd.Lookup(ip, &a); err != nil {
			continue
		}
		if a.AutonomousSystemNumber == 0 && a.AutonomousSystemOrganization == "" {
			continue
		}
		res.ASN = int(a.AutonomousSystemNumber)
		res.Org = a.AutonomousSystemOrganization
		if !res.IsHosting && looksLikeHosting(res.Org) {
			res.IsHosting = true
		}
		return
	}
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// pickName ưu tiên tên tiếng Anh → bất kỳ tên nào → fallback (mã ISO).
func pickName(names map[string]string, fallback string) string {
	if names != nil {
		if v := strings.TrimSpace(names["en"]); v != "" {
			return v
		}
		for _, v := range names {
			if v = strings.TrimSpace(v); v != "" {
				return v
			}
		}
	}
	return fallback
}

// hostingKeywords gợi ý tổ chức là datacenter/hosting/VPN/cloud (fallback best-effort).
var hostingKeywords = []string{
	"hosting", "host", "data center", "datacenter", "data-center",
	"cloud", "vps", "server", "colocation", "colo", "vpn", "proxy",
	"digitalocean", "linode", "ovh", "hetzner", "vultr", "amazon", "aws",
	"google cloud", "microsoft azure", "azure", "alibaba cloud", "tencent cloud",
}

func looksLikeHosting(org string) bool {
	if org == "" {
		return false
	}
	low := strings.ToLower(org)
	for _, kw := range hostingKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// privateNets là các dải IP nội bộ. IP thuộc các dải này được gắn IsInternal, KHÔNG tra DB.
var privateNets = func() []*net.IPNet {
	cidrs := []string{
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
		"127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
		"::1/128", "fc00::/7", "fe80::/10",
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

func isInternalIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
