# edge-guardian — common dev tasks. Run `make help` for the list.
BINARY      := edge-guardian
PKG         := ./cmd/edge-guardian
VERSION     ?= dev
LDFLAGS     := -s -w -X main.version=$(VERSION)
DIST        := dist

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | \
		awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

TEMPL := $(shell command -v templ 2>/dev/null || echo $(HOME)/go/bin/templ)

.PHONY: tools
tools: ## Install codegen tools (templ)
	go install github.com/a-h/templ/cmd/templ@latest

.PHONY: generate
generate: ## Generate templ components (*_templ.go) for the dashboard
	$(TEMPL) generate ./internal/web

.PHONY: build
build: generate ## Build the binary natively (stub enforcer off-Linux)
	go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY) $(PKG)

.PHONY: build-linux
build-linux: generate ## Cross-compile a static Linux amd64 binary (real nftables)
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 $(PKG)

.PHONY: test
test: ## Run all tests with the race detector and coverage
	go test -race -cover ./...

.PHONY: cover
cover: ## Write and open a coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

.PHONY: vet
vet: ## Static analysis on both target platforms
	go vet ./...
	GOOS=linux GOARCH=amd64 go vet ./...

.PHONY: fmt
fmt: ## Format all Go files
	gofmt -w .

.PHONY: check
check: fmt vet test ## Format, vet, and test — run before committing

.PHONY: tidy
tidy: ## Tidy module dependencies
	go mod tidy

.PHONY: demo
demo: ## Run a local dry-run playground with the dashboard (macOS/Linux)
	bash dev/demo.sh

.PHONY: packages
packages: ## Build .deb + .rpm for amd64+arm64 (needs nfpm)
	bash dev/build-packages.sh $(VERSION)

.PHONY: image
image: ## Build the Docker image (edge-guardian:latest)
	docker build -t edge-guardian:latest .

.PHONY: test-packages
test-packages: ## Build + test .deb/.rpm/image on real Linux containers (needs Docker)
	bash dev/test-packages.sh

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(DIST) coverage.out dev/run
