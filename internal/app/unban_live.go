package app

import (
	"context"
	"fmt"
)

// UnbanLive removes an IP from the RUNNING daemon: deletes it from nftables, from the
// in-memory state (so it isn't reloaded after a restart), from the sliding window, then saves state.
//
// This is the shared unban path for the control socket and the dashboard's Unban button.
// Concurrency-safe with the pipeline: state.Store, the enforcer, and the window each have their own lock.
func (a *App) UnbanLive(ctx context.Context, ip string) error {
	addr, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("unban: %w", err)
	}
	key := addr.String()

	// Dry-run adds nothing to nftables, so there's nothing to remove either.
	if !a.d.DryRun {
		if err := a.d.Enforcer.Unban(addr); err != nil {
			return fmt.Errorf("unban %s: nftables: %w", key, err)
		}
	}

	a.d.State.Remove(key)
	for _, det := range a.d.Detectors {
		det.Window.Forget(key)
	}

	if err := a.d.State.Save(); err != nil {
		return fmt.Errorf("unban %s: applied to nftables+memory but state save failed (will re-ban on restart): %w", key, err)
	}

	a.d.Logger.Info("unbanned (live)", "ip", key, "dry_run", a.d.DryRun)
	return nil
}
