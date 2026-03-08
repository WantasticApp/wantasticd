# Makefile for Wantastic desktop app
# Wails is now the primary build tool — the project root is the Go package.

# Go parameters
GOCMD=go
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE?=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS="-s -w -X wantastic-agent/pkg/version.Version=$(VERSION) -X wantastic-agent/pkg/version.Commit=$(COMMIT) -X wantastic-agent/pkg/version.BuildDate=$(DATE)"
GOBUILD=$(GOCMD) build -ldflags=$(LDFLAGS)
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
BINARY_NAME=wantastic
COMPRESS=upx -9 -v
WAILS_TAGS=nosystray

# ── Primary desktop build (Wails) ────────────────────────────────────────────
# Wails injects required build tags and embeds the frontend automatically.
# All desktop builds MUST use `wails build`; never use plain `go build` for them.

# Install frontend dependencies
deps:
	cd gui/frontend && pnpm install

# Hot-reload dev mode (Vite + Go, live editing)
dev:
	WANTASTIC_PORTAL_URL=http://wantastic.local wails dev -tags $(WAILS_TAGS)

# Alias kept for convenience
gui-dev: dev

# Production desktop build → bin/wantastic (current platform)
build:
	WANTASTIC_PORTAL_URL=https://console.wantastic.app wails build -tags $(WAILS_TAGS) -o bin/$(BINARY_NAME)

# Run production build straight after building
run:
	WANTASTIC_PORTAL_URL=https://console.wantastic.app wails build -tags $(WAILS_TAGS) -o bin/$(BINARY_NAME) && ./bin/$(BINARY_NAME)

# macOS arm64 (Apple Silicon)
build-mac:
	WANTASTIC_PORTAL_URL=https://console.wantastic.app wails build -tags $(WAILS_TAGS) -platform darwin/arm64 -o bin/$(BINARY_NAME)-darwin-arm64

# Windows amd64
build-windows:
	WANTASTIC_PORTAL_URL=https://console.wantastic.app wails build -tags $(WAILS_TAGS) -platform windows/amd64 -o bin/$(BINARY_NAME)-windows-amd64.exe

# Linux amd64
build-linux:
	WANTASTIC_PORTAL_URL=https://console.wantastic.app wails build -tags $(WAILS_TAGS) -platform linux/amd64 -o bin/$(BINARY_NAME)-linux-amd64

# ── Headless cross-compiled binaries (no GUI, for routers / servers) ─────────
# These targets produce lightweight headless builds (no Wails, no frontend).
# Build tags: nosystray disables the tray; noegtui disables Wails webview.
HEADLESS_LDFLAGS="-s -w -X wantastic-agent/pkg/version.Version=$(VERSION) -X wantastic-agent/pkg/version.Commit=$(COMMIT) -X wantastic-agent/pkg/version.BuildDate=$(DATE)"
GOBUILD_HEADLESS=$(GOCMD) build -tags nosystray -ldflags=$(HEADLESS_LDFLAGS)

CROSS_TARGETS := \
	linux/386 \
	linux/amd64 \
	linux/arm \
	linux/arm64 \
	linux/loong64 \
	linux/mips \
	linux/mips64 \
	linux/mips64le \
	linux/mipsle \
	linux/ppc64 \
	linux/ppc64le \
	linux/riscv64 \
	linux/s390x \
	windows/amd64

build-all:
	@for target in $(CROSS_TARGETS); do \
		echo "Building headless for $$target"; \
		mkdir -p bin; \
		GOOS=$$(echo $$target | cut -d'/' -f1) GOARCH=$$(echo $$target | cut -d'/' -f2) \
			$(GOBUILD_HEADLESS) -o bin/$(BINARY_NAME)-$$(echo $$target | tr '/' '-') internal/agent/...; \
	done
	@echo "Building headless for linux/armv7"
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD_HEADLESS) -o bin/$(BINARY_NAME)-linux-armv7 ./internal/agent/...

# ── Utilities ─────────────────────────────────────────────────────────────────

clean:
	$(GOCLEAN)
	rm -rf bin

genproto:
	protoc -Iproto --go_out=internal/grpc/proto --go_opt=paths=source_relative \
		--go-grpc_out=internal/grpc/proto --go-grpc_opt=paths=source_relative \
		auth.proto

test:
	$(GOTEST) -v ./...

# Copy icon into the Wails build directory
install-icons:
	@echo "Installing icons…"
	@mkdir -p gui/build
	@cp /Users/kimo/Desktop/kmoz000/ISPApp-TunnelHub/cmd/web/portal/app/public/logo/512.png \
	     gui/build/appicon.png
	@cp /Users/kimo/Desktop/kmoz000/ISPApp-TunnelHub/cmd/web/portal/app/public/logo/512.png \
	     gui/frontend/public/logo.png
	@echo "Icons installed."

release:
	git tag -a $(firstword $(filter-out release,$(MAKECMDGOALS))) -m "Release $(firstword $(filter-out release,$(MAKECMDGOALS)))"
	git push origin $(firstword $(filter-out release,$(MAKECMDGOALS)))

.PHONY: all build build-all build-mac build-windows build-linux clean run dev gui-dev \
        deps genproto test install-icons release
