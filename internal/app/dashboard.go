package app

import (
	"context"
	"time"

	"github.com/sondt/edge-guardian/internal/geoip"
	"github.com/sondt/edge-guardian/internal/health"
	"github.com/sondt/edge-guardian/internal/state"
	"github.com/sondt/edge-guardian/internal/web"
)

// dashboardData adapts the daemon's live state to web.DataSource: it lists active
// bans (enriched with GeoIP), per-site health, and routes the Unban action through the
// in-process live-unban path (state + nftables + persist).
type dashboardData struct {
	state        *state.Store
	geo          GeoIP
	app          *App
	now          func() time.Time
	health       *health.Health
	healthWindow int
}

// geoFields turns a geoip.Result into the (country, asn-label) strings the dashboard
// ledger and ban events display. Internal IPs read "Internal".
func geoFields(r geoip.Result) (country, asn string) {
	if r.IsInternal {
		return "Internal", ""
	}
	return r.Country, r.ASNLabel()
}

// Bans returns the currently active bans as the dashboard ledger read model.
func (d dashboardData) Bans() []web.Ban {
	entries := d.state.Active(d.now())
	out := make([]web.Ban, 0, len(entries))
	for _, e := range entries {
		detector := e.Detector
		if detector == "" {
			detector = "http" // tolerate entries written before the detector field existed
		}
		geo := d.geo.Lookup(e.IP)
		country, asn := geoFields(geo)
		out = append(out, web.Ban{
			IP:        e.IP,
			Detector:  detector,
			Reason:    e.Reason,
			FirstSeen: e.FirstSeen,
			ExpiresAt: e.ExpiresAt,
			Country:   country,
			ASN:       asn,
			Location:  geo.Place(),
			Hits:      e.Hits,
		})
	}
	return out
}

// Unban removes a ban from the running daemon (live).
func (d dashboardData) Unban(ctx context.Context, ip string) error {
	return d.app.UnbanLive(ctx, ip)
}

// SiteHealth returns the per-site health read model for the dashboard. Empty when the
// health branch is disabled.
func (d dashboardData) SiteHealth() []web.SiteHealth {
	if d.health == nil {
		return nil
	}
	stats := d.health.SnapshotAll(d.healthWindow)
	out := make([]web.SiteHealth, 0, len(stats))
	for _, s := range stats {
		out = append(out, web.SiteHealth{
			Host:        s.Host,
			Status:      s.Status,
			Reqs:        s.Reqs,
			ReqPerSec:   s.ReqPerSec,
			Err5xxPct:   s.Err5xxRatio * 100,
			HasLatency:  s.HasLatency,
			P95Sec:      s.P95Sec,
			UpstreamErr: s.UpstreamErr,
			Spark:       s.Spark,
		})
	}
	return out
}

// webSink adapts a *web.Store to the app.EventSink interface so the pipeline can push
// detection events without the hot path depending on web's concrete Event type.
type webSink struct {
	store *web.Store
}

func (w webSink) Push(at time.Time, ip, detector, action, country, asn string) {
	w.store.Push(web.Event{
		At:       at,
		IP:       ip,
		Detector: detector,
		Action:   action,
		Country:  country,
		ASN:      asn,
	})
}
