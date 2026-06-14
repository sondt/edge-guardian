//go:build linux

package enforce

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/nftables"
)

// nftEnforcer thao tác nftables qua netlink (không exec lệnh `nft`).
type nftEnforcer struct {
	cfg Config

	mu    sync.Mutex
	conn  *nftables.Conn
	table *nftables.Table
	set4  *nftables.Set
	set6  *nftables.Set
}

func newPlatform(cfg Config) (Enforcer, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("open nftables netlink: %w", err)
	}

	table := &nftables.Table{Family: nftables.TableFamilyINet, Name: cfg.Table}

	set4, err := conn.GetSetByName(table, cfg.SetV4)
	if err != nil {
		return nil, fmt.Errorf("lookup set %q (run setup-nftables.sh?): %w", cfg.SetV4, err)
	}
	set6, err := conn.GetSetByName(table, cfg.SetV6)
	if err != nil {
		return nil, fmt.Errorf("lookup set %q (run setup-nftables.sh?): %w", cfg.SetV6, err)
	}

	return &nftEnforcer{cfg: cfg, conn: conn, table: table, set4: set4, set6: set6}, nil
}

func (e *nftEnforcer) Ban(ip netip.Addr, timeout time.Duration) error {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return fmt.Errorf("ban: invalid ip")
	}
	// A nftables element timeout of 0 means "never expire". Refuse non-positive
	// durations so a caller bug can't silently create a permanent ban.
	if timeout <= 0 {
		return fmt.Errorf("ban: timeout must be positive, got %v", timeout)
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	set := e.set4
	if ip.Is6() {
		set = e.set6
	}
	elem := nftables.SetElement{
		Key:     ip.AsSlice(),
		Timeout: timeout,
	}
	if err := e.conn.SetAddElements(set, []nftables.SetElement{elem}); err != nil {
		return fmt.Errorf("nft add element %s: %w", ip, err)
	}
	if err := e.conn.Flush(); err != nil {
		return fmt.Errorf("nft flush (ban %s): %w", ip, err)
	}
	return nil
}

func (e *nftEnforcer) Unban(ip netip.Addr) error {
	ip = ip.Unmap()
	if !ip.IsValid() {
		return fmt.Errorf("unban: invalid ip")
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	set := e.set4
	if ip.Is6() {
		set = e.set6
	}
	elem := nftables.SetElement{Key: ip.AsSlice()}
	if err := e.conn.SetDeleteElements(set, []nftables.SetElement{elem}); err != nil {
		return fmt.Errorf("nft delete element %s: %w", ip, err)
	}
	// The kernel surfaces the actual delete result on Flush. A missing element
	// (e.g. the ban already expired) returns ENOENT, which is not an error per the
	// Enforcer contract — the IP is already not banned.
	if err := e.conn.Flush(); err != nil {
		if errors.Is(err, syscall.ENOENT) {
			return nil
		}
		return fmt.Errorf("nft flush (unban %s): %w", ip, err)
	}
	return nil
}

// ReplaceBlockset nạp lại toàn bộ interval set blockset4/blockset6 bằng `nft -f -`.
// Đây là CỐ TÌNH dùng exec (không netlink): nạp hàng nghìn CIDR vào interval set là
// thao tác BULK định kỳ (không phải hot-path ban từng IP), và `nft -f` xử lý interval
// set tin cậy hơn nhiều so với tự dựng phần tử interval qua netlink.
func (e *nftEnforcer) ReplaceBlockset(v4, v6 []netip.Prefix) error {
	var b strings.Builder
	writeSet := func(name string, prefixes []netip.Prefix) {
		fmt.Fprintf(&b, "flush set inet %s %s\n", e.cfg.Table, name)
		if len(prefixes) == 0 {
			return
		}
		fmt.Fprintf(&b, "add element inet %s %s { ", e.cfg.Table, name)
		for i, p := range prefixes {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(p.String())
		}
		b.WriteString(" }\n")
	}
	writeSet(e.cfg.BlockSetV4, v4)
	writeSet(e.cfg.BlockSetV6, v6)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft -f (replace blockset): %w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (e *nftEnforcer) Close() error {
	return e.conn.CloseLasting()
}
