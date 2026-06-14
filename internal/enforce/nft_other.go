//go:build !linux

package enforce

import (
	"fmt"
	"net/netip"
	"runtime"
	"time"
)

// stubEnforcer cho phép build/test trên OS không phải Linux (vd macOS dev).
// Mọi thao tác ban thật trả về lỗi rõ ràng — chỉ Linux + nftables mới enforce được.
type stubEnforcer struct{}

func newPlatform(Config) (Enforcer, error) {
	return stubEnforcer{}, nil
}

func unsupported(op string) error {
	return fmt.Errorf("enforce.%s: nftables enforcement is only available on Linux (running on %s); build with GOOS=linux", op, runtime.GOOS)
}

func (stubEnforcer) Ban(netip.Addr, time.Duration) error { return unsupported("Ban") }
func (stubEnforcer) Unban(netip.Addr) error              { return unsupported("Unban") }
func (stubEnforcer) ReplaceBlockset([]netip.Prefix, []netip.Prefix) error {
	return unsupported("ReplaceBlockset")
}
func (stubEnforcer) Close() error { return nil }
