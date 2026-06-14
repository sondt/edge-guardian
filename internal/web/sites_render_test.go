package web

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func healthConfig(t *testing.T) Config {
	c := testConfig(t)
	c.HealthWindowMins = 180
	return c
}

func TestSitesPageRenders(t *testing.T) {
	data := &fakeDataSource{sites: []SiteHealth{
		{Host: "ok.example", Status: "Healthy", Reqs: 1000, ReqPerSec: 120, Err5xxPct: 0.3, HasLatency: true, P95Sec: 1.1, Spark: []int{1, 2, 3, 2, 4}},
		{Host: "bad.example", Status: "Degraded", Reqs: 400, ReqPerSec: 38, Err5xxPct: 12.4, HasLatency: true, P95Sec: 1.8, UpstreamErr: 3, Spark: []int{5, 3, 2, 1, 1}},
	}}
	store := NewStore(time.Hour)
	s := New(healthConfig(t), data, store)
	cookies := login(t, s)

	rec := authedGet(t, s, "/sites", cookies)
	if rec.Code != http.StatusOK {
		t.Fatalf("sites: want 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"Site health", "ok.example", "bad.example", "Degraded", "12.4%", "1.8s", "3 err", "1.1s"} {
		if !strings.Contains(body, want) {
			t.Fatalf("sites body missing %q", want)
		}
	}
}

func TestSitesPageEmptyState(t *testing.T) {
	store := NewStore(time.Hour)
	s := New(healthConfig(t), &fakeDataSource{}, store)
	cookies := login(t, s)
	rec := authedGet(t, s, "/sites", cookies)
	if !strings.Contains(rec.Body.String(), "No site data yet") {
		t.Fatalf("expected empty-state copy, got: %s", rec.Body.String())
	}
}

func TestOverviewShowsSiteHealthReadout(t *testing.T) {
	data := &fakeDataSource{sites: []SiteHealth{
		{Host: "a.example", Status: "Down", Reqs: 10},
		{Host: "b.example", Status: "Degraded", Reqs: 200, Err5xxPct: 8},
	}}
	store := NewStore(time.Hour)
	s := New(healthConfig(t), data, store)
	cookies := login(t, s)
	rec := authedGet(t, s, "/", cookies)
	body := rec.Body.String()
	for _, want := range []string{"Site health", "Down", "1 down", "1 degraded"} {
		if !strings.Contains(body, want) {
			t.Fatalf("overview readout missing %q", want)
		}
	}
}

func TestNavHidesSitesWhenHealthDisabled(t *testing.T) {
	// HealthWindowMins == 0 → health off → no Sites nav link.
	store := NewStore(time.Hour)
	s := New(testConfig(t), &fakeDataSource{}, store)
	cookies := login(t, s)
	rec := authedGet(t, s, "/", cookies)
	if strings.Contains(rec.Body.String(), `href="/sites"`) {
		t.Fatal("Sites nav link should be hidden when health is disabled")
	}
}

func TestSitesViewMapping(t *testing.T) {
	v := toSiteView(SiteHealth{Host: "x", Status: "Down", ReqPerSec: 5.2, Err5xxPct: 50, HasLatency: false, UpstreamErr: 0})
	if v.StatusClass != "is-down" || v.StatusDot != "✕" {
		t.Fatalf("status styling wrong: %+v", v)
	}
	if v.ReqPerSec != "5.2" {
		t.Fatalf("req/s fmt=%q want 5.2", v.ReqPerSec)
	}
	if v.UpstreamErr != "" {
		t.Fatalf("zero upstream should be empty, got %q", v.UpstreamErr)
	}

	sum := summarizeSites([]SiteHealth{{Status: "Healthy"}, {Status: "Degraded"}, {Status: "Down"}})
	if sum.State != "Down" || sum.Degraded != 1 || sum.Down != 1 || sum.Total != 3 {
		t.Fatalf("summary wrong: %+v", sum)
	}
}
