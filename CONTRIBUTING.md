# Contributing to edge-guardian

Thanks for your interest. edge-guardian aims to stay small, fast, and dependency-light.
Contributions are evaluated against that goal first.

## Principles

- **Single static binary.** No runtime services, no databases. New features must not
  require external infrastructure to run the free, self-hosted edition. (Go's static
  builds and trivial cross-compilation are a core reason for the language choice.)
- **Safe by default.** Detection must minimise false positives. Anything that can ban a
  real user needs an allowlist path and a dry-run story.
- **One pipeline.** Every detector flows through the same path (read → detect → enforce →
  notify). Adding a source should be a parser + a threshold, not a rewrite — see
  `internal/app/Detector`.
- **Readable over clever.** This is security software; clarity beats micro-optimisation.

## Getting set up

Requires **Go 1.26+**. On macOS the nftables enforcer is a build-tagged stub, so
everything builds and the pure logic is fully testable; real firewall behaviour only runs
on Linux.

```bash
go build ./...                          # native (stub enforcer off-Linux)
GOOS=linux GOARCH=amd64 go build ./...  # the real Linux build
go test -race ./...                     # and: go vet ./... ; gofmt -l .
make demo                               # local dashboard playground (dry-run)
```

The dashboard UI uses [templ](https://templ.guide). The generated `*_templ.go` files are
committed (so a plain `go build` works), but if you edit a `.templ` file, regenerate:

```bash
make tools && make generate   # or: ~/go/bin/templ generate ./internal/web
```

## Testing the Linux-only parts

The nftables enforcer, the kernel-log detectors, and the packages can't run on macOS.
There are Docker harnesses that exercise them on real Linux:

```bash
bash dev/docker-test.sh       # real nftables enforce/unban + detection + blocklist
bash dev/test-packages.sh     # install/upgrade/remove the .deb and .rpm, build the image
```

CI (`.github/workflows/ci.yml`) runs `go test -race`, vet, gofmt, a GoReleaser build, and
the real-nftables integration on every push/PR. Releases are cut by pushing a `v*` tag.

## Pull requests

1. For anything non-trivial, open an issue first so we can agree on the approach.
2. Keep PRs focused — one concern per PR.
3. Include tests for parsing, detection, and state logic (`go test -race`). Pure logic
   must be platform-independent.
4. Run `gofmt`, `go vet ./...`, and `GOOS=linux go vet ./...` before pushing.
5. Update the relevant docs under `docs/` (currently maintained in Vietnamese) and the
   config reference if you add a config key.

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org)
(`feat:`, `fix:`, `refactor:`, `docs:`, `test:`, `chore:`, `perf:`, `ci:`) — the release
changelog is generated from them.

## Reporting security issues

**Do not open public issues for vulnerabilities.** See [SECURITY.md](SECURITY.md) for how
to report privately.
