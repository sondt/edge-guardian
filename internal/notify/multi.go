package notify

import (
	"context"
	"errors"
)

// multi gửi mỗi sự kiện tới NHIỀU kênh. Một kênh lỗi không chặn các kênh khác —
// lỗi được gộp lại (errors.Join) để caller log.
type multi struct {
	notifiers []Notifier
}

// Multi gộp nhiều Notifier thành một. Không có kênh nào → Noop; đúng một kênh → trả
// thẳng kênh đó (khỏi bọc thừa).
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

// Notify gửi tới mọi kênh, gộp lỗi (không fail-fast).
func (m multi) Notify(ctx context.Context, ev Event) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.Notify(ctx, ev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// NotifyHealth fan-out cảnh báo sức khỏe tới mọi kênh, gộp lỗi.
func (m multi) NotifyHealth(ctx context.Context, ev HealthEvent) error {
	var errs []error
	for _, n := range m.notifiers {
		if err := n.NotifyHealth(ctx, ev); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
