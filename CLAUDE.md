# CLAUDE.md — edge-guardian

Hướng dẫn cho Claude Code khi làm việc trong repo này. Đọc cùng các rule trong
`.claude/rules/` mỗi session.

## Sản phẩm là gì

edge-guardian là **intrusion prevention daemon** cho Linux, đóng gói một **binary tĩnh
duy nhất** (Go). Luồng cốt lõi:

```text
log (nginx/sshd/kernel) → parse → detect (ngưỡng + cửa sổ trượt)
   → allowlist? → ban qua nftables (timeout) → notify (Telegram)
```

Triết lý: **đơn giản cực đoan** — cài một dòng, trỏ vào log, quên đi. Không database,
không service phụ; state lưu trong một file JSON.

Tài liệu thiết kế đầy đủ (tiếng Việt) ở [`docs/`](docs/). Đọc theo thứ tự
`01 → 02 → 03 → 04`. Sản phẩm (binary, config, log, README công khai) mặc định
tiếng Anh; docs nội bộ tiếng Việt.

## Ngôn ngữ & nền tảng

- **Go 1.26+** (toolchain dev: 1.26.4), ưu tiên stdlib. Chỉ thêm dependency khi rõ ràng đáng giá
  (xem `docs/02-kien-truc.md` bảng thư viện).
- Mục tiêu chạy: **Linux + nftables**. Build cross-compile từ Mac:
  `GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o edge-guardian ./cmd/edge-guardian`.
- **nftables là Linux-only.** Code thao tác nftables nằm sau build tag
  (`//go:build linux`) trong `internal/enforce/`, kèm một stub `!linux` để toàn bộ
  module vẫn `go build` / `go test` được trên macOS dev. Mọi logic thuần (parse,
  detect, state, config, allowlist) phải độc lập nền tảng và có test.

## Cấu trúc

```text
cmd/edge-guardian/        entrypoint: flag, nạp config, chạy daemon, subcommand `unban`
internal/config/     đọc & validate config TOML (+ defaults)
internal/parse/      parser dòng log → ip, uri
internal/detect/     matcher pattern URI + sliding-window threshold
internal/allow/      allowlist CIDR (net/netip)
internal/state/      state.json: load/save (atomic) / prune / restore
internal/enforce/    nftables ban/unban/restore (build-tag Linux) + stub
internal/notify/     interface Notifier + telegram + resend(email) + multi fan-out
internal/geoip/      IP → vị trí/mạng (maxminddb trực tiếp; file sapics miễn phí; comma-paths)
internal/blocklist/  import blocklist công khai (FireHOL/Spamhaus) → nftables interval set
internal/ingest/     tail log + theo dõi rotation
internal/control/    unix control socket (server+client) cho `unban` khi daemon chạy
internal/web/        dashboard local: Chi + templ + HTMX, asset nhúng (Phase 2)
internal/app/        lắp ráp & vòng lặp daemon (Service orchestration, live-unban)
```

Build dashboard cần bước codegen templ trước khi `go build`:
`~/go/bin/templ generate ./internal/web` (sinh `*_templ.go`).

Quy ước: **nhiều file nhỏ** (200–400 dòng, tối đa 800), tổ chức theo domain,
`internal/` để không bị import từ ngoài. `cmd/edge-guardian` mỏng, chỉ lắp ráp.

## Nguyên tắc khi viết code ở đây

- **An toàn mặc định.** Bất cứ thứ gì có thể ban người dùng thật phải đi qua
  allowlist và có đường dry-run. `detection.dry_run = true` → phát hiện + log + notify
  "SẼ ban" nhưng KHÔNG chạm nftables.
- **Bất biến** dữ liệu chia sẻ; trả về copy thay vì mutate input (xem
  `.claude/rules/common/coding-style.md`).
- **Đọc log → quyết định → thực thi** là pipeline duy nhất cho mọi nguồn phát hiện.
  Thêm nguồn mới = thêm parser + cấu hình ngưỡng, không phá khung.
- **Wrap lỗi có ngữ cảnh** (`fmt.Errorf("...: %w", err)`), structured log `log/slog`.
- nftables: thao tác **native qua netlink** (`github.com/google/nftables`), KHÔNG
  exec lệnh `nft` qua subprocess. `setup-nftables.sh` chỉ dựng khung table/set/chain.

## Lệnh hay dùng

```bash
go build ./...                         # build native (dùng stub enforce trên Mac)
GOOS=linux GOARCH=amd64 go build ./... # build thật cho Linux (enforce nftables)
go test -race ./...                    # test (logic thuần độc lập nền tảng)
go vet ./...                           # và: GOOS=linux go vet ./...
gofmt -l -w .
make demo                              # playground dashboard (dry-run, macOS/Linux)
make packages                          # .deb/.rpm (amd64+arm64) via nfpm
make test-packages                     # test deb/rpm/image trên container Linux thật
bash dev/docker-test.sh                # validate enforcer/detection nftables thật
```

## CI/CD & release

Repo: **github.com/sondt/edge-guardian** (private). `.github/workflows/ci.yml` chạy trên
push/PR (gofmt, vet, `go test -race`, cross-compile, goreleaser snapshot, và một job
integration nftables THẬT qua `dev/docker-test.sh`). `release.yml` chạy khi push tag
`v*`: GoReleaser (`.goreleaser.yaml`) build binaries + `.deb`/`.rpm` + Docker image
multi-arch → ghcr.io + GitHub Release. Cắt release: `git tag vX.Y.Z && git push --tags`.

Lưu ý CI: trên Linux runner, các test gọi `app.Build` sẽ **skip** nếu nftables chưa
khởi tạo (enforcer thật cần table); pipeline test dùng `fakeEnforcer`.

## Trạng thái & phạm vi hiện tại

Phase 1 (free core). Đã làm trong Go: HTTP scanner, **SSH brute-force**, **port scan**
(đếm distinct port), **honeypot port** detection, nftables ban + timeout, Telegram +
GeoIP tùy chọn, state + restore sau reboot, allowlist CIDR, **dry-run**, **CLI `unban`**
(+ control socket), **dashboard web** (xem `DESIGN.md`), **email (Resend) + Telegram**
(multi-channel), **import blocklist công khai** (FireHOL/Spamhaus → nftables interval
set). Phase 1 free core coi như đầy đủ — xem [`docs/08-lo-trinh.md`](docs/08-lo-trinh.md).

Detector dùng **Counter** (`detect.Hits` đếm hit, `detect.NewDistinct` đếm port distinct
cho port scan). Nguồn port scan/honeypot là kernel netfilter LOG (nft `log prefix`)
route ra file rồi tail như mọi log khác.

**Detection engine đa nguồn:** mỗi nguồn là một `app.Detector` ({Name, Inspect, Window}).
Daemon chạy mọi detector trên mỗi dòng log (pattern rời nhau nên không trùng). Thêm
nguồn mới = thêm một `Detector` trong `buildDetectors` + parser trong `internal/parse`,
không sửa pipeline. State entry mang `Detector` + `Reason`.

## Không làm (non-goals giai đoạn này)

Full SIEM, WAF OWASP CRS đầy đủ, crowd-sourced blocklist, phụ thuộc dịch vụ ngoài
cho bản self-hosted. Xem `docs/01-tong-quan.md`.
