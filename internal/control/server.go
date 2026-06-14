package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"syscall"
	"time"
)

// maxRequestBytes bounds how much a client can send before json decode — a valid
// request is tiny; this caps memory against a hostile local writer.
const maxRequestBytes = 4096

// Unbanner là hành động daemon thực hiện khi nhận lệnh unban.
type Unbanner interface {
	UnbanLive(ctx context.Context, ip string) error
}

// Server lắng nghe trên một unix socket và phục vụ các Request.
// Triển khai app.Service (Start/Name).
type Server struct {
	path string
	unb  Unbanner
	log  *slog.Logger
}

// NewServer tạo control server gắn với hành động unban của daemon.
func NewServer(path string, unb Unbanner, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{path: path, unb: unb, log: log}
}

// Name định danh service trong log.
func (s *Server) Name() string { return "control-socket" }

// Start lắng nghe cho tới khi ctx hủy. Xóa socket cũ (nếu có), tạo mới với quyền
// 0600, accept và xử lý từng kết nối. Khi ctx hủy, đóng listener và dọn socket.
func (s *Server) Start(ctx context.Context) error {
	// Dọn socket mồ côi từ lần chạy trước (crash không kịp xóa).
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("control: could not remove stale socket", "path", s.path, "err", err)
	}

	// Tạo socket với quyền 0600 NGAY từ đầu bằng umask, tránh khe TOCTOU giữa
	// listen và chmod (umask 0177 => file mode 0600).
	oldMask := syscall.Umask(0o177)
	ln, err := net.Listen("unix", s.path)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("control: listen on %q: %w", s.path, err)
	}
	// Defense-in-depth: đảm bảo quyền 0600 kể cả khi umask không tác dụng như mong đợi.
	if err := os.Chmod(s.path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("control: chmod socket %q: %w", s.path, err)
	}
	// Dọn socket khi thoát (UnixListener.Close cũng unlink, đây là belt-and-suspenders).
	defer os.Remove(s.path)
	s.log.Info("control socket listening", "path", s.path)

	// Đóng listener khi ctx hủy để bung Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // shutdown bình thường
			}
			s.log.Error("control: accept failed", "err", err)
			continue
		}
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	var req Request
	if err := json.NewDecoder(io.LimitReader(conn, maxRequestBytes)).Decode(&req); err != nil {
		s.writeResp(conn, Response{OK: false, Error: "invalid request: " + err.Error()})
		return
	}

	switch req.Cmd {
	case "ping":
		s.writeResp(conn, Response{OK: true})
	case "unban":
		if req.IP == "" {
			s.writeResp(conn, Response{OK: false, Error: "unban requires ip"})
			return
		}
		if err := s.unb.UnbanLive(ctx, req.IP); err != nil {
			s.writeResp(conn, Response{OK: false, Error: err.Error()})
			return
		}
		s.writeResp(conn, Response{OK: true})
	default:
		s.writeResp(conn, Response{OK: false, Error: "unknown command: " + req.Cmd})
	}
}

func (s *Server) writeResp(conn net.Conn, resp Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		s.log.Debug("control: write response failed", "err", err)
	}
}
