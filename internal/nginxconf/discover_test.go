package nginxconf

import (
	"reflect"
	"testing"
)

func TestParseServerNames(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "multiple blocks and names, deduped + sorted",
			in: `
server {
    listen 80;
    server_name example.com www.example.com;
}
server {
    listen 443 ssl;
    server_name example.com;   # https of the same site
    server_name api.example.com;
}`,
			want: []string{"api.example.com", "example.com", "www.example.com"},
		},
		{
			name: "drops catch-all and regex names",
			in: `server_name _;
server_name ~^www\.(?<domain>.+)$;
server_name shop.vn;`,
			want: []string{"shop.vn"},
		},
		{
			name: "keeps wildcard, lowercases",
			in:   `server_name *.Example.COM Sub.Site.VN;`,
			want: []string{"*.example.com", "sub.site.vn"},
		},
		{name: "none", in: "worker_processes auto;\nhttp { }", want: []string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseServerNames(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("parseServerNames() = %v, want %v", got, tt.want)
			}
		})
	}
}
