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

// Unbanner is the action the daemon performs when it receives an unban command.
type Unbanner interface {
	UnbanLive(ctx context.Context, ip string) error
}

// Server listens on a unix socket and serves Requests.
// It implements app.Service (Start/Name).
type Server struct {
	path string
	unb  Unbanner
	log  *slog.Logger
}

// NewServer creates a control server bound to the daemon's unban action.
func NewServer(path string, unb Unbanner, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{path: path, unb: unb, log: log}
}

// Name identifies the service in logs.
func (s *Server) Name() string { return "control-socket" }

// Start listens until ctx is canceled. It removes any old socket, creates a new one with
// mode 0600, and accepts and handles each connection. When ctx is canceled, it closes the
// listener and cleans up the socket.
func (s *Server) Start(ctx context.Context) error {
	// Clean up an orphaned socket from a previous run (a crash left it behind).
	if err := os.Remove(s.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		s.log.Warn("control: could not remove stale socket", "path", s.path, "err", err)
	}

	// Create the socket with mode 0600 right from the start via umask, avoiding a TOCTOU
	// window between listen and chmod (umask 0177 => file mode 0600).
	oldMask := syscall.Umask(0o177)
	ln, err := net.Listen("unix", s.path)
	syscall.Umask(oldMask)
	if err != nil {
		return fmt.Errorf("control: listen on %q: %w", s.path, err)
	}
	// Defense-in-depth: ensure mode 0600 even if umask did not take effect as expected.
	if err := os.Chmod(s.path, 0o600); err != nil {
		_ = ln.Close()
		return fmt.Errorf("control: chmod socket %q: %w", s.path, err)
	}
	// Clean up the socket on exit (UnixListener.Close also unlinks; this is belt-and-suspenders).
	defer os.Remove(s.path)
	s.log.Info("control socket listening", "path", s.path)

	// Close the listener when ctx is canceled to unblock Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // normal shutdown
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
