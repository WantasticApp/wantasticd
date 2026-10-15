SHELL := /bin/sh
.DEFAULT_GOAL := help

GO ?= go
PNPM ?= pnpm
WAILS_VERSION ?= v3.0.0-beta.29
WAILS := $(GO) run github.com/wailsapp/wails/v3/cmd/wails3@$(WAILS_VERSION)

APP_NAME := wantastic
CLI_NAME := wantasticd
CLI_PACKAGE := ./cmd/wantasticd
BIN_DIR := bin
DESKTOP_BIN_DIR := build/bin
FRONTEND_DIR := gui/frontend

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 'dev')
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf 'unknown')
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
HOST_OS := $(shell $(GO) env GOOS)
MACOSX_DEPLOYMENT_TARGET ?= 13.0

VERSION_INFO_LDFLAGS := -X wantastic-agent/pkg/version.Version=$(VERSION) \
	-X wantastic-agent/pkg/version.Commit=$(COMMIT) \
	-X wantastic-agent/pkg/version.BuildDate=$(BUILD_DATE)
CLI_LDFLAGS := -s -w $(VERSION_INFO_LDFLAGS)
DESKTOP_LDFLAGS := $(VERSION_INFO_LDFLAGS)
ifeq ($(HOST_OS),darwin)
DESKTOP_LDFLAGS += -extldflags=-mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
endif
ifeq ($(HOST_OS),linux)
DESKTOP_TAGS ?= gtk3
endif

CLI_TARGETS := darwin/amd64 darwin/arm64 linux/386 linux/amd64 linux/arm linux/arm64 \
	linux/loong64 linux/mips linux/mips64 linux/mips64le linux/mipsle linux/ppc64 \
	linux/ppc64le linux/riscv64 linux/s390x windows/386 windows/amd64 windows/arm64

.PHONY: help all build cli cli-all test test-cli test-desktop vet vet-cli vet-desktop \
	check audit frontend-install frontend-build frontend-audit bindings desktop desktop-build \
	desktop-package desktop-dev desktop-task desktop-macos-universal install-check clean version

help: ## Show supported build, test, and development targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-26s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: check build ## Run checks and build the CLI

build: cli ## Build the host CLI

cli: ## Build the host wantasticd binary
	@mkdir -p "$(BIN_DIR)"
	$(GO) build -trimpath -tags nosystray -ldflags="$(CLI_LDFLAGS)" -o "$(BIN_DIR)/$(CLI_NAME)" $(CLI_PACKAGE)

cli-all: ## Cross-compile all release CLI targets
	@set -eu; \
	mkdir -p "$(BIN_DIR)"; \
	for target in $(CLI_TARGETS); do \
		goos=$${target%/*}; \
		goarch=$${target#*/}; \
		extension=; \
		if [ "$$goos" = windows ]; then extension=.exe; fi; \
		printf 'Building %s/%s\n' "$$goos" "$$goarch"; \
		GOOS="$$goos" GOARCH="$$goarch" CGO_ENABLED=0 $(GO) build \
			-trimpath -tags nosystray -ldflags="$(CLI_LDFLAGS)" \
			-o "$(BIN_DIR)/$(CLI_NAME)-$$goos-$$goarch$$extension" $(CLI_PACKAGE); \
	done

test: test-cli ## Run the portable Go test suite

test-cli: ## Run CLI, agent, networking, and platform-independent tests
	CGO_ENABLED=0 $(GO) test -tags nosystray ./assets ./cmd/... ./internal/... ./pkg/...

test-desktop: ## Run host-native desktop and privileged-helper tests
	$(GO) test . ./internal/auth ./internal/claimkey ./internal/config ./internal/agent ./internal/device ./internal/netctl ./internal/netprobe ./cmd/wantasticd

vet: vet-cli ## Vet portable Go packages

vet-cli: ## Vet CLI and platform-independent packages
	CGO_ENABLED=0 $(GO) vet -tags nosystray ./assets ./cmd/... ./internal/... ./pkg/...

vet-desktop: ## Vet the host-native desktop application
	$(GO) vet . ./internal/auth ./internal/claimkey ./internal/config ./internal/agent ./internal/device ./internal/netctl ./internal/netprobe ./cmd/wantasticd

check: test-cli vet-cli frontend-audit install-check ## Run the release quality gates
	@git diff --check

audit: ## Scan the built CLI for reachable Go vulnerabilities
	@mkdir -p "$(BIN_DIR)"
	CGO_ENABLED=0 $(GO) build -trimpath -tags nosystray -o "$(BIN_DIR)/$(CLI_NAME)-audit" $(CLI_PACKAGE)
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest -mode=binary "$(BIN_DIR)/$(CLI_NAME)-audit"

frontend-install: ## Install pinned frontend dependencies
	cd "$(FRONTEND_DIR)" && $(PNPM) install --frozen-lockfile

frontend-build: frontend-install ## Generate bindings and build the embedded frontend
	$(WAILS) generate bindings -clean=true -ts -d "$(FRONTEND_DIR)/src/bindings" .
	cd "$(FRONTEND_DIR)" && $(PNPM) run build

frontend-audit: ## Audit production frontend dependencies
	cd "$(FRONTEND_DIR)" && $(PNPM) audit --prod

bindings: ## Regenerate Wails TypeScript bindings
	$(WAILS) generate bindings -clean=true -ts -d "$(FRONTEND_DIR)/src/bindings" .

desktop: desktop-build ## Build the desktop app for the host platform

desktop-build: ## Build the Wails desktop app for the host platform
	$(WAILS) task "$(HOST_OS):build" EXTRA_TAGS="$(DESKTOP_TAGS)" WANTASTIC_LDFLAGS='$(DESKTOP_LDFLAGS)'

desktop-package: ## Package the Wails desktop app for the host platform
	$(WAILS) task "$(HOST_OS):package" EXTRA_TAGS="$(DESKTOP_TAGS)" WANTASTIC_LDFLAGS='$(DESKTOP_LDFLAGS)'

desktop-task: ## Run DESKTOP_TASK (used by the cross-platform CI matrix)
	@test -n "$(DESKTOP_TASK)" || { printf 'DESKTOP_TASK is required\n' >&2; exit 2; }
	$(WAILS) task "$(DESKTOP_TASK)" EXTRA_TAGS="$(DESKTOP_TAGS)" WANTASTIC_LDFLAGS='$(DESKTOP_LDFLAGS)'

desktop-macos-universal: ## Build and ad-hoc sign the universal macOS app
	@test "$(HOST_OS)" = darwin || { printf 'This target requires macOS\n' >&2; exit 2; }
	$(WAILS) task darwin:package:universal WANTASTIC_LDFLAGS='$(DESKTOP_LDFLAGS)'

desktop-dev: ## Run the desktop app with frontend hot reload
	$(WAILS) dev -config ./build/config.yml

install-check: ## Validate maintained installer scripts
	sh -n install.sh internal/update/self-update.sh e2e/run_p2p_test.sh e2e/docker-compose/entrypoint.sh

version: ## Print build identity
	@printf 'version=%s commit=%s date=%s\n' "$(VERSION)" "$(COMMIT)" "$(BUILD_DATE)"

clean: ## Remove local build outputs only
	$(GO) clean
	@test -n "$(BIN_DIR)" && test "$(BIN_DIR)" != / && rm -rf -- "$(BIN_DIR)"
	@test -n "$(DESKTOP_BIN_DIR)" && test "$(DESKTOP_BIN_DIR)" != / && rm -rf -- "$(DESKTOP_BIN_DIR)"
