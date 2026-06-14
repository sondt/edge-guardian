<!-- Thanks for contributing! Keep PRs focused — one concern each. -->

## What & why

<!-- What does this change, and why? Link the issue: Closes #123 -->

## Checklist

- [ ] `go test -race ./...` passes
- [ ] `gofmt -l .` is clean and `go vet ./...` (+ `GOOS=linux go vet ./...`) passes
- [ ] Tests added/updated for new parsing/detection/state logic (platform-independent)
- [ ] If I touched `.templ` files, I ran `make generate` and committed the `*_templ.go`
- [ ] Docs under `docs/` (and the config reference, if a config key changed) updated
- [ ] Conventional Commit title (`feat:` / `fix:` / `docs:` / …)

## Notes for the reviewer

<!-- Anything Linux-only that needs `bash dev/docker-test.sh`, tradeoffs, follow-ups -->
