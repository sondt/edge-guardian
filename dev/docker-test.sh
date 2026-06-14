#!/usr/bin/env bash
# End-to-end validation of edge-guardian on REAL Linux + nftables, inside a privileged
# container. Run from the repo root on a machine with Docker:
#   bash dev/docker-test.sh
#
# Validates the parts that can't run on macOS:
#  - the real nftables enforcer (Ban/Unban via netlink) populating the blocklist set
#  - honeypot (instant ban) + port-scan (distinct-port) detection from netfilter LOG
#  - setup-nftables.sh log rules actually matching scan traffic (rule counters)
#  - `edge-guardian unban` removing an IP from the live nftables set
set -euo pipefail
cd "$(dirname "$0")/.."

GOOS=linux GOARCH=amd64 go build -ldflags="-s -w -X main.version=docker-test" \
  -o dist/edge-guardian-linux-amd64 ./cmd/edge-guardian
echo "==> built linux binary"

docker run --rm --privileged -v "$PWD:/repo" -w /repo debian:12-slim bash /repo/dev/docker-test-inner.sh
