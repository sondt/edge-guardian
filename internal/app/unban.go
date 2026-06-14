package app

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/sondt/edge-guardian/internal/config"
	"github.com/sondt/edge-guardian/internal/enforce"
	"github.com/sondt/edge-guardian/internal/state"
)

// Unban gỡ một IP khỏi CẢ nftables set VÀ state.json, để IP không bị nạp lại sau
// khi daemon restart. Đây là điểm UX docs nêu cần một lệnh xử lý cả hai nơi.
func Unban(cfg config.Config, logger *slog.Logger, ip string) error {
	addr, err := parseAddr(ip)
	if err != nil {
		return fmt.Errorf("unban: %w", err)
	}

	st, err := state.Load(cfg.State.Path, time.Now(), 0)
	if err != nil {
		return fmt.Errorf("unban: load state: %w", err)
	}
	removedState := st.Remove(addr.String())

	enf, err := enforce.New(enforce.Config{
		Table: cfg.Ban.NftTable,
		SetV4: cfg.Ban.NftSetV4,
		SetV6: cfg.Ban.NftSetV6,
	})
	if err != nil {
		return fmt.Errorf("unban: init enforcer: %w", err)
	}
	defer enf.Close()

	if err := enf.Unban(addr); err != nil {
		return fmt.Errorf("unban: remove from nftables: %w", err)
	}
	if err := st.Save(); err != nil {
		return fmt.Errorf("unban: save state: %w", err)
	}

	logger.Info("unbanned", "ip", addr.String(), "was_in_state", removedState)
	return nil
}
