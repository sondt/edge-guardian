#!/usr/bin/env bash
# Build .deb and .rpm packages for amd64 + arm64 using nfpm. Run from repo root:
#   bash dev/build-packages.sh [version]
# Output: dist/edge-guardian_<version>_<arch>.{deb,rpm}
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${1:-${EDGEGUARD_VERSION:-0.1.0}}"
NFPM="${NFPM:-$(command -v nfpm || echo "$HOME/go/bin/nfpm")}"
[ -x "$NFPM" ] || { echo "nfpm not found — go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest" >&2; exit 1; }

mkdir -p dist
# Ensure templ-generated files exist (committed, but regenerate if templ is available).
command -v templ >/dev/null 2>&1 && templ generate ./internal/web >/dev/null 2>&1 || true

render_config() { # ARCH VERSION BIN -> rendered nfpm config on stdout
  sed -e "s|\${ARCH}|$1|g" -e "s|\${VERSION}|$2|g" -e "s|\${BIN}|$3|g" packaging/nfpm.yaml
}

for ARCH in amd64 arm64; do
  echo "==> building binary linux/$ARCH"
  BIN="dist/edge-guardian-linux-$ARCH"
  GOOS=linux GOARCH="$ARCH" go build -ldflags="-s -w -X main.version=$VERSION" -o "$BIN" ./cmd/edge-guardian

  CFG="dist/nfpm-$ARCH.yaml"
  render_config "$ARCH" "$VERSION" "$BIN" > "$CFG"
  echo "==> packaging deb + rpm ($ARCH $VERSION)"
  "$NFPM" package --config "$CFG" --packager deb --target "dist/edge-guardian_${VERSION}_${ARCH}.deb"
  "$NFPM" package --config "$CFG" --packager rpm --target "dist/edge-guardian-${VERSION}.${ARCH}.rpm"
  rm -f "$CFG"
done

echo
echo "==> built packages:"
ls -lh dist/*.deb dist/*.rpm
