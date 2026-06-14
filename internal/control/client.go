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

// ErrDaemonNotRunning báo không kết nối được control socket — daemon nhiều khả năng
// không chạy, caller có thể chuyển sang đường xử lý offline.
var ErrDaemonNotRunning = errors.New("control: daemon not running (socket unavailable)")

// SendUnban gửi lệnh unban tới daemon đang chạy qua socket.
// Trả về ErrDaemonNotRunning nếu không kết nối được (để caller fallback offline).
func SendUnban(socketPath, ip string) error {
	return send(socketPath, Request{Cmd: "unban", IP: ip})
}

func send(socketPath string, req Request) error {
	conn, err := net.DialTimeout("unix", socketPath, 3*time.Second)
	if err != nil {
		// Socket không tồn tại hoặc không ai lắng nghe => daemon không chạy.
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

// isConnRefused báo lỗi dial là ECONNREFUSED (socket tồn tại nhưng không ai lắng
// nghe) — daemon không chạy. KHÔNG gộp các lỗi dial khác (vd EACCES quyền truy cập)
// để tránh che giấu lỗi thật bằng đường offline.
func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}
