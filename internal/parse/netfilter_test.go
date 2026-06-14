package parse

import "testing"

const scanLine = `Jun 14 10:00:00 host kernel: EDGEGUARD-SCAN IN=eth0 OUT= MAC=aa:bb SRC=185.220.101.5 DST=10.0.0.1 LEN=60 TOS=0x00 PREC=0x00 TTL=51 ID=1 DF PROTO=TCP SPT=44321 DPT=2222 WINDOW=1024 RES=0x00 SYN URGP=0`

func TestNetfilterParser(t *testing.T) {
	scan := NewNetfilterParser("EDGEGUARD-SCAN")

	t.Run("matches scan line", func(t *testing.T) {
		ev, ok := scan.Parse(scanLine)
		if !ok {
			t.Fatal("should parse scan line")
		}
		if ev.IP != "185.220.101.5" || ev.Port != "2222" {
			t.Fatalf("got ip=%q port=%q want 185.220.101.5/2222", ev.IP, ev.Port)
		}
	})

	t.Run("wrong prefix ignored", func(t *testing.T) {
		hp := NewNetfilterParser("EDGEGUARD-HONEYPOT")
		if _, ok := hp.Parse(scanLine); ok {
			t.Fatal("honeypot parser must not match a scan line")
		}
	})

	t.Run("honeypot line", func(t *testing.T) {
		hp := NewNetfilterParser("EDGEGUARD-HONEYPOT")
		line := `host kernel: EDGEGUARD-HONEYPOT IN=eth0 SRC=45.13.22.7 DST=10.0.0.1 PROTO=TCP SPT=5 DPT=23 SYN`
		ev, ok := hp.Parse(line)
		if !ok || ev.IP != "45.13.22.7" || ev.Port != "23" {
			t.Fatalf("got %+v ok=%v", ev, ok)
		}
	})

	t.Run("ipv6 source", func(t *testing.T) {
		line := `kernel: EDGEGUARD-SCAN SRC=2001:db8::dead DST=2001:db8::1 PROTO=TCP SPT=1 DPT=8080`
		ev, ok := scan.Parse(line)
		if !ok || ev.IP != "2001:db8::dead" || ev.Port != "8080" {
			t.Fatalf("got %+v ok=%v", ev, ok)
		}
	})

	t.Run("unrelated line", func(t *testing.T) {
		if _, ok := scan.Parse("just some log line"); ok {
			t.Fatal("non-matching line should not parse")
		}
	})

	t.Run("missing DPT", func(t *testing.T) {
		if _, ok := scan.Parse("kernel: EDGEGUARD-SCAN SRC=1.2.3.4 PROTO=ICMP"); ok {
			t.Fatal("line without DPT should not parse")
		}
	})
}
