package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

// ErrDaemonNotRunning signals the control socket could not be reached — the daemon
// is most likely not running, and the caller may fall back to offline handling.
var ErrDaemonNotRunning = errors.New("control: daemon not running (socket unavailable)")

// SendUnban sends an unban command to the running daemon over the socket.
// Returns ErrDaemonNotRunning if the connection fails (so the caller can fall back offline).
func SendUnban(socketPath, ip string) error {
	return send(socketPath, Request{Cmd: "unban", IP: ip})
}

func send(socketPath string, req Request) error {
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		// Socket does not exist or nobody is listening => daemon not running.
		if errors.Is(err, os.ErrNotExist) || isConnRefused(err) {
			return ErrDaemonNotRunning
		}
		return fmt.Errorf("control: dial %q: %w", socketPath, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return fmt.Errorf("control: send request: %w", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("control: read response: %w", err)
	}
	if !resp.OK {
		return fmt.Errorf("control: daemon refused: %s", resp.Error)
	}
	return nil
}

// isConnRefused reports whether the dial error is ECONNREFUSED (the socket exists but
// nobody is listening) — daemon not running. It does NOT lump in other dial errors
// (e.g. EACCES permission) to avoid masking a real error with the offline path.
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
