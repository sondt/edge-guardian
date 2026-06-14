# edge-guardian container image. Multi-stage: build a static binary, run on a slim base
# that carries the `nft` binary (needed for the public-blocklist import) + CA certs.
#
# Run it to protect the HOST firewall (manages the host's nftables, reads host logs):
#   docker run -d --name edge-guardian \
#     --network host --cap-add NET_ADMIN \
#     -v /etc/edge-guardian:/etc/edge-guardian \
#     -v /var/log/nginx:/var/log/nginx:ro \
#     -v edge-guardian-state:/var/lib/edge-guardian \
#     ghcr.io/giaiphapmoipro/edge-guardian
# (Initialize the firewall once on the host first: bash setup-nftables.sh)
FROM golang:1.26-bookworm AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# templ-generated files are committed, so no codegen needed.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=docker" -o /edge-guardian ./cmd/edge-guardian

FROM debian:12-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends nftables ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /edge-guardian /usr/bin/edge-guardian
COPY config.example.toml /usr/share/edge-guardian/config.example.toml
COPY setup-nftables.sh /usr/share/edge-guardian/setup-nftables.sh
VOLUME /var/lib/edge-guardian
ENTRYPOINT ["/usr/bin/edge-guardian"]
CMD ["--config", "/etc/edge-guardian/config.toml"]
