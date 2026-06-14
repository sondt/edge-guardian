---
name: golang-patterns
description: Comprehensive Go idioms and patterns for edge-guardian — package layout, small interfaces, dependency injection, error wrapping, concurrency with context, and platform-specific code via build tags. Use when writing or reviewing Go code in this repo.
origin: edge-guardian
---

# Go Patterns (edge-guardian)

Idioms for the edge-guardian daemon. Extends `.claude/rules/golang/patterns.md`.
Goal: a single static binary, stdlib-first, readable over clever.

## When to Activate

- Writing or reviewing any `.go` file in this repo
- Adding a new detection source, notifier channel, or enforcement backend
- Deciding where an interface or type should live

## Package & file layout

- One concern per package under `internal/` (config, parse, detect, allow, state,
  enforce, notify, geoip, ingest, app). `cmd/edge-guardian` stays thin — it only wires.
- Many small files (200–400 lines, 800 max). Split by role, not by type.
- Pure logic (parse, detect, state, config, allow) must be platform-independent and
  unit-tested. I/O wrappers (enforce, ingest, geoip, telegram) stay thin.

## Interfaces

- **Accept interfaces, return structs.** Keep interfaces 1–3 methods.
- **Define interfaces where they are used**, not where implemented. Example:
  `enforce.Enforcer`, `notify.Notifier`, `geoip.Lookup` are consumed by `app`.
- Provide a no-op implementation for optional collaborators (`notify.Noop`,
  `geoip.Empty`) so the daemon degrades gracefully when a feature is off.

## Dependency injection

Wire concrete deps in a constructor; inject fakes in tests. edge-guardian uses a `Deps`
struct + `app.New(Deps)` so the pipeline is testable without nftables/Telegram/files.
Inject a `Now func() time.Time` for deterministic time in tests.

```go
type Deps struct {
    Enforcer enforce.Enforcer
    Notifier notify.Notifier
    Now      func() time.Time // nil => time.Now
}
```

## Error handling

Always wrap with context using `%w`:

```go
if err != nil {
    return fmt.Errorf("nft add element %s: %w", ip, err)
}
```

Never silently swallow errors. Validate external input at boundaries
(`config.Validate`, regex named groups, CIDR parsing) and fail fast with clear
messages. Log detailed context server-side via `log/slog`.

## Immutability

Return copies of shared data; never mutate a caller's slice/map. `allow.New` copies
the prefix slice; `state.Store.Active` returns value copies, not aliases into the map.

## Concurrency

- One goroutine per log source feeding a shared channel; a single consumer drives the
  pipeline (bans are rare, so no lock contention on the hot path).
- Use `context.Context` for cancellation and timeouts (e.g. Telegram has a per-call
  timeout; the daemon stops on `SIGINT/SIGTERM` via `signal.NotifyContext`).
- Guard shared maps (`detect.Window`, `state.Store`) with a `sync.Mutex`.
- Run `go test -race ./...` — the race detector must stay clean.

## Platform-specific code (build tags)

nftables is Linux-only (native netlink). Keep the interface platform-neutral and put
the real impl behind a build tag, with a stub for other OSes so `go build`/`go test`
work on macOS dev:

```go
// nft_linux.go  -> //go:build linux      (imports github.com/google/nftables)
// nft_other.go  -> //go:build !linux     (stub returning a clear "Linux only" error)
```

Always verify both: `go build ./...` and `GOOS=linux GOARCH=amd64 go build ./...`.

## Stdlib first

Prefer `net/http`, `net/netip`, `regexp` (RE2), `log/slog`, `encoding/json`, `flag`.
Add a third-party module only when it clearly pays for itself (see the library table
in `docs/02-kien-truc.md`).

## Atomic file writes

Persist state via temp file + `Sync` + `os.Rename` to survive a crash mid-write
(see `internal/state`).
