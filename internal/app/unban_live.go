package app

import (
	"context"
	"fmt"
)

// UnbanLive gỡ một IP khỏi daemon ĐANG CHẠY: xóa khỏi nftables, khỏi state
// in-memory (nên không bị nạp lại sau restart), khỏi cửa sổ trượt, rồi lưu state.
//
// Đây là đường unban dùng chung cho control socket và nút Unban của dashboard.
// An toàn đồng thời với pipeline: state.Store, enforcer và window đều có khóa riêng.
func (a *App) UnbanLive(ctx context.Context, ip string) error {
	addr, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("unban: %w", err)
	}
	key := addr.String()

	// Dry-run không thêm gì vào nftables nên cũng không cần gỡ.
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
