package notify

import (
	"context"
	"errors"
)

// multi sends each event to MULTIPLE channels. One failing channel does not block the
// others — errors are joined (errors.Join) for the caller to log.
type multi struct {
	notifiers []Notifier
}

// Multi combines several Notifiers into one. No channels → Noop; exactly one channel → return
// that channel directly (avoid needless wrapping).
func Multi(notifiers ...Notifier) Notifier {
	switch len(notifiers) {
	case 0:
		return Noop{}
	case 1:
		return notifiers[0]
	default:
		return multi{notifiers: notifiers}
	}
}

// Notify sends to every channel, joining errors (no fail-fast).
func (m multi) Notify(ctx context.Context, ev Event) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Notify(ctx, ev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NotifyHealth fans out the health alert to every channel, joining errors.
func (m multi) NotifyHealth(ctx context.Context, ev HealthEvent) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.NotifyHealth(ctx, ev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
