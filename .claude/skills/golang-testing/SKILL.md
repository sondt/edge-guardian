---
name: golang-testing
description: Go testing patterns and helpers for edge-guardian — table-driven tests, the -race flag, deterministic clocks, fakes for I/O collaborators, httptest for the Telegram client, and integration tests over real temp log files. Use when adding or reviewing Go tests in this repo.
origin: edge-guardian
---

# Go Testing (edge-guardian)

Extends `.claude/rules/golang/testing.md` and `common/testing.md`. Target: **80%+**
coverage on testable logic, all tests pass under `-race`.

## When to Activate

- Writing tests for new detection logic, parsers, config, state, or the pipeline
- Reviewing a PR that adds or changes Go behavior
- Diagnosing flaky or time-dependent tests

## Commands

```bash
go test -race -cover ./...        # default — race detector + coverage
go test -run TestName ./internal/detect
go test -coverprofile=coverage.out ./... && go tool cover -func=coverage.out
```

## TDD loop

RED (write a failing test) → GREEN (minimal impl) → REFACTOR. Write the test first
for new detection sources and parsing logic — those are the highest-risk areas.

## Table-driven tests

Default style. Name sub-tests; cover the boundary and the negative case.

```go
tests := []struct{ uri string; want bool }{
    {"/wp-login.php", true},
    {"/index.PHP", true},   // case-insensitive
    {"/api/users", false},  // clean path must NOT match
}
for _, tt := range tests {
    t.Run(tt.uri, func(t *testing.T) {
        if got := m.IsBad(tt.uri); got != tt.want {
            t.Fatalf("IsBad(%q)=%v want %v", tt.uri, got, tt.want)
        }
    })
}
```

## Deterministic time

Never call `time.Now()` directly in logic under test. Inject a clock and pin it:

```go
fixed := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
d := app.Deps{ /* ... */, Now: func() time.Time { return fixed } }
```

Sliding-window and ban-expiry tests pass explicit timestamps so they are stable.

## Fakes for I/O collaborators

Replace nftables/Telegram/GeoIP with fakes implementing the small interfaces. A fake
enforcer records `Ban`/`Unban` calls; a fake notifier counts events. This lets the
whole pipeline run on macOS without root or netlink. Guard fake counters with a mutex
so `-race` stays clean.

## HTTP clients — httptest, never the network

Test the Telegram notifier against `httptest.NewServer` and a `RoundTripper` that
rewrites `api.telegram.org` to the test server. Assert both the success path and a
non-200 error path (error must surface the API description).

## Filesystem & integration

- Use `t.TempDir()` for state files and temp logs — auto-cleaned, parallel-safe.
- For the run loop, write a real temp log file, start `App.Run` in a goroutine with a
  cancellable context, append a scanner line, and poll a condition with a timeout
  helper (`waitFor`). Always `cancel()` and join the goroutine at the end.

## What not to over-test

Thin platform/I/O wrappers (`enforce` nftables calls, `geoip` mmdb reads, `ingest`
tail) can't be meaningfully unit-tested on macOS — cover them via the integration
test and the cross-compile build (`GOOS=linux go build ./...`), and keep the pure
logic coverage high. Fix the implementation, not the test, when a real test fails.
