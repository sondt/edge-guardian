package web

import (
	"testing"
	"time"
)

func seedErrors(s *Store, base time.Time) {
	rows := []ErrorReq{
		{At: base.Add(1 * time.Minute), Host: "a.com", IP: "1.1.1.1", Path: "/x", Status: 404},
		{At: base.Add(2 * time.Minute), Host: "a.com", IP: "2.2.2.2", Path: "/y", Status: 500},
		{At: base.Add(3 * time.Minute), Host: "b.com", IP: "3.3.3.3", Path: "/z", Status: 502},
		{At: base.Add(4 * time.Minute), Host: "b.com", IP: "4.4.4.4", Path: "/login", Status: 403},
	}
	for _, e := range rows {
		s.PushError(e)
	}
}

func TestErrors_NewestFirstAndCount(t *testing.T) {
	s := NewStore(time.Hour)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	seedErrors(s, base)

	p := s.Errors(ErrorFilter{})
	if p.TotalAll != 4 || p.Total != 4 {
		t.Fatalf("counts wrong: TotalAll=%d Total=%d", p.TotalAll, p.Total)
	}
	if len(p.Items) != 4 {
		t.Fatalf("items=%d want 4", len(p.Items))
	}
	if p.Items[0].Path != "/login" { // newest first
		t.Fatalf("not newest-first: %q", p.Items[0].Path)
	}
	if len(p.Hosts) != 2 || p.Hosts[0] != "a.com" || p.Hosts[1] != "b.com" {
		t.Fatalf("hosts wrong: %v", p.Hosts)
	}
}

func TestErrors_Filters(t *testing.T) {
	s := NewStore(time.Hour)
	seedErrors(s, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))

	if got := s.Errors(ErrorFilter{Host: "a.com"}).Total; got != 2 {
		t.Fatalf("host filter: %d want 2", got)
	}
	if got := s.Errors(ErrorFilter{Class: "5xx"}).Total; got != 2 {
		t.Fatalf("5xx filter: %d want 2", got)
	}
	if got := s.Errors(ErrorFilter{Class: "4xx"}).Total; got != 2 {
		t.Fatalf("4xx filter: %d want 2", got)
	}
	if got := s.Errors(ErrorFilter{Search: "LOGIN"}).Total; got != 1 { // case-insensitive
		t.Fatalf("search path: %d want 1", got)
	}
	if got := s.Errors(ErrorFilter{Search: "3.3.3.3"}).Total; got != 1 {
		t.Fatalf("search ip: %d want 1", got)
	}
	if got := s.Errors(ErrorFilter{Host: "b.com", Class: "5xx"}).Total; got != 1 {
		t.Fatalf("combined filter: %d want 1", got)
	}
}

func TestErrors_Pagination(t *testing.T) {
	s := NewStore(time.Hour)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range 120 {
		s.PushError(ErrorReq{At: base.Add(time.Duration(i) * time.Second), Host: "a.com", IP: "1.1.1.1", Path: "/p", Status: 500})
	}
	p1 := s.Errors(ErrorFilter{Page: 1})
	if p1.PerPage != ErrorsDefaultPerPage || len(p1.Items) != ErrorsDefaultPerPage {
		t.Fatalf("page1 size=%d perPage=%d", len(p1.Items), p1.PerPage)
	}
	if p1.Pages != 3 { // 120 / 50 = 3 pages
		t.Fatalf("pages=%d want 3", p1.Pages)
	}
	p3 := s.Errors(ErrorFilter{Page: 3})
	if len(p3.Items) != 20 {
		t.Fatalf("page3 size=%d want 20", len(p3.Items))
	}
	// Out-of-range page clamps to the last page.
	if got := s.Errors(ErrorFilter{Page: 99}).Page; got != 3 {
		t.Fatalf("clamp page=%d want 3", got)
	}
}

func TestErrors_BufferCap(t *testing.T) {
	s := NewStore(time.Hour)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range ErrorBufferCap + 500 {
		s.PushError(ErrorReq{At: base.Add(time.Duration(i) * time.Second), Path: "/p", Status: 500})
	}
	if got := s.Errors(ErrorFilter{}).TotalAll; got != ErrorBufferCap {
		t.Fatalf("cap not enforced: %d want %d", got, ErrorBufferCap)
	}
}
