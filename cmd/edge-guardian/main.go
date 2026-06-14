// Command edge-guardian: intrusion prevention daemon — reads logs, detects scanners,
// bans IPs via nftables, sends notifications. See docs/ for the detailed design.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"

	"github.com/sondt/edge-guardian/internal/app"
	"github.com/sondt/edge-guardian/internal/config"
	"github.com/sondt/edge-guardian/internal/control"
	"github.com/sondt/edge-guardian/internal/ingest"
)

// version is set via -ldflags "-X main.version=..." at release time.
var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "edge-guardian: "+err.Error())
		os.Exit(1)
	}
}

func run(args []string) error {
	logger := newLogger()

	fs := flag.NewFlagSet("edge-guardian", flag.ContinueOnError)
	configPath := fs.String("config", "/etc/edge-guardian/config.toml", "path to config file")
	fs.StringVar(configPath, "c", "/etc/edge-guardian/config.toml", "path to config file (shorthand)")
	showVersion := fs.Bool("version", false, "print version and exit")
	fs.Usage = func() { usage(fs) }
	if err := fs.Parse(args); err != nil {
		return err
	}

	if *showVersion {
		fmt.Println("edge-guardian", version)
		return nil
	}

	// Subcommand: edge-guardian [flags] unban <ip>
	switch fs.Arg(0) {
	case "unban":
		ip := fs.Arg(1)
		if ip == "" {
			return fmt.Errorf("usage: edge-guardian unban <ip>")
		}
		cfg, err := config.Load(*configPath)
		if err != nil {
			return err
		}
		return unbanCommand(cfg, logger, ip)
	case "hash-password":
		return hashPasswordCommand(fs.Arg(1))
	case "":
		return runDaemon(*configPath, logger)
	default:
		return fmt.Errorf("unknown command %q (try: unban, hash-password)", fs.Arg(0))
	}
}

// hashPasswordCommand prints a bcrypt hash for the dashboard password, so operators
// don't need htpasswd. Reads from the argument or, if empty, from stdin.
func hashPasswordCommand(pw string) error {
	if pw == "" {
		data, err := io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read password from stdin: %w", err)
		}
		pw = strings.TrimRight(string(data), "\r\n")
	}
	if pw == "" {
		return fmt.Errorf("usage: edge-guardian hash-password <password>  (or pipe it on stdin)")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), 12)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}
	fmt.Println(string(h))
	return nil
}

// unbanCommand removes an IP. If the daemon is running (control socket available), it
// sends the command over the socket to immediately update the in-memory state +
// nftables. If the daemon is not running, it handles it offline directly on the state
// file + nftables.
func unbanCommand(cfg config.Config, logger *slog.Logger, ip string) error {
	if cfg.Control.Enabled {
		err := control.SendUnban(cfg.Control.SocketPath, ip)
		switch {
		case err == nil:
			logger.Info("unban sent to running daemon", "ip", ip)
			return nil
		case errors.Is(err, control.ErrDaemonNotRunning):
			logger.Info("daemon not running; unbanning offline", "ip", ip)
			// fall through to the offline path below
		default:
			return err
		}
	}
	return app.Unban(cfg, logger, ip)
}

func runDaemon(configPath string, logger *slog.Logger) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	comps, err := app.Build(cfg, logger)
	if err != nil {
		return err
	}
	defer comps.Cleanup()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Info("edge-guardian starting",
		"version", version,
		"paths", cfg.Log.Paths,
		"dry_run", cfg.Detection.DryRun,
		"threshold", cfg.Detection.Threshold,
		"window_secs", cfg.Detection.WindowSecs,
	)

	tailer := ingest.New(comps.App.Paths())
	if err := comps.App.Run(ctx, tailer, comps.Services...); err != nil && err != context.Canceled {
		return err
	}
	logger.Info("edge-guardian stopped")
	return nil
}

func newLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	h := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}

func usage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `edge-guardian — intrusion prevention daemon

Usage:
  edge-guardian [--config PATH]            run the daemon
  edge-guardian [--config PATH] unban IP   remove an IP from nftables and state
  edge-guardian hash-password PASSWORD     print a bcrypt hash for the dashboard
  edge-guardian --version                  print version

Flags:
`)
	fs.PrintDefaults()
	fmt.Fprintln(os.Stderr, "\nEnv: LOG_LEVEL=debug|info|warn|error")
}
