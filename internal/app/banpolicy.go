package app

import "time"

// banDurationFor returns the ban duration for an offense, per the escalation policy.
// offenseIdx is the NUMBER OF PRIOR BANS (0 = first offense). Empty escalation → flat ban
// (always uses flat). A repeat offense beyond the list length → uses the last tier (e.g. "permanent").
func banDurationFor(offenseIdx int, escalation []time.Duration, flat time.Duration) time.Duration {
	if len(escalation) == 0 {
		return flat
	}
	if offenseIdx < 0 {
		offenseIdx = 0
	}
	if offenseIdx >= len(escalation) {
		offenseIdx = len(escalation) - 1
	}
	return escalation[offenseIdx]
}
