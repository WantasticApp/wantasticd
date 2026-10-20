SHELL := /bin/sh
.DEFAULT_GOAL := help

GO ?= go
SWIFT ?= swift
XCODEGEN ?= xcodegen
DEVELOPER_DIR := $(shell xcode-select -p 2>/dev/null)
TESTING_FRAMEWORK_DIR := $(DEVELOPER_DIR)/Library/Developer/Frameworks
TESTING_RUNTIME_DIR := $(DEVELOPER_DIR)/Library/Developer/usr/lib

ifneq ($(wildcard $(TESTING_FRAMEWORK_DIR)/Testing.framework),)
SWIFT_TEST_FLAGS += -Xswiftc -F -Xswiftc $(TESTING_FRAMEWORK_DIR) \
	-Xlinker -rpath -Xlinker $(TESTING_FRAMEWORK_DIR) \
	-Xlinker -rpath -Xlinker $(TESTING_RUNTIME_DIR)
endif

CLI_NAME := wantasticd
CLI_PACKAGE := ./cmd/wantasticd
BIN_DIR := bin

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || printf 'dev')
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf 'unknown')
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ')

VERSION_INFO_LDFLAGS := -X wantastic-agent/pkg/version.Version=$(VERSION) \
	-X wantastic-agent/pkg/version.Commit=$(COMMIT) \
	-X wantastic-agent/pkg/version.BuildDate=$(BUILD_DATE)
CLI_LDFLAGS := -s -w $(VERSION_INFO_LDFLAGS)

CLI_TARGETS := darwin/amd64 darwin/arm64 linux/386 linux/amd64 linux/arm linux/arm64 \
	linux/loong64 linux/mips linux/mips64 linux/mips64le linux/mipsle linux/ppc64 \
	linux/ppc64le linux/riscv64 linux/s390x windows/386 windows/amd64 windows/arm64

.PHONY: help all build cli cli-all test test-go test-cli test-swift vet vet-cli \
	check audit macos-build macos-test macos-xcode-test macos-local-app macos-run-local \
	install-check clean version

help: ## Show supported build, test, and development targets
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_.-]+:.*## / {printf "  %-26s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

all: check build ## Run Go and Swift checks, then build the wantasticd CLI

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

test: test-go test-swift ## Run the full Go compatibility and native macOS Swift test suites

test-go: ## Run all Go unit and integration tests, including protocol compatibility
	$(GO) test ./... -count=1

test-cli: ## Run CLI, agent, networking, and platform-independent tests
	CGO_ENABLED=0 $(GO) test -tags nosystray ./cmd/... ./internal/... ./pkg/...

test-swift: ## Run the native macOS Swift tests and source-set type-checks
	$(SWIFT) build
	test -s "$$($(SWIFT) build --show-bin-path)/WantasticMac_WantasticApp.bundle/WantasticLogoSwiftPM.png"
	swiftc -typecheck -swift-version 6 -D WANTASTIC_XCODE_APP -I "$$($(SWIFT) build --show-bin-path)/Modules" \
		Sources/WantasticApp/WantasticApp.swift Sources/WantasticTunnel/TunnelController.swift \
		Sources/WantasticTunnel/SystemExtensionActivator.swift
	swiftc -typecheck -swift-version 6 -D WANTASTIC_SYSTEM_EXTENSION_ENTRY -I "$$($(SWIFT) build --show-bin-path)/Modules" \
		Sources/WantasticTunnel/PacketFlowRouteSender.swift Sources/WantasticTunnel/PacketTunnelProvider.swift \
		Sources/WantasticTunnel/SystemExtensionMain.swift Sources/WantasticTunnel/TunnelNetworkSettingsBuilder.swift \
		Sources/WantasticTunnel/WireGuardPeerTransport.swift Sources/WantasticTunnel/WireGuardUDPConnection.swift \
		Sources/WantasticTunnel/MacLocalAccessFirewallController.swift \
		Sources/WantasticTunnel/MacLocalAccessRouteCoordinator.swift \
		Sources/WantasticTunnel/MacLocalAccessProviderManager.swift \
		Sources/WantasticTunnel/XPCMacLocalAccessFirewallSystem.swift
	$(SWIFT) test $(SWIFT_TEST_FLAGS)

macos-build: ## Build the native macOS Swift app and helper package
	$(SWIFT) build --configuration release

macos-test: test-swift ## Alias for the native macOS Swift test suite

macos-xcode-test: ## Generate and test native Xcode app/extension targets (requires full Xcode)
	$(XCODEGEN) generate
	plutil -lint Config/Wantastic.entitlements Config/WantasticTunnel.entitlements \
		Config/WantasticTunnel-Info.plist Config/app.wantastic.desktop.local-access-helper.plist \
		WantasticMac.xcodeproj/project.pbxproj
	xcodebuild -project WantasticMac.xcodeproj -scheme Wantastic \
		-destination 'platform=macOS' CODE_SIGNING_ALLOWED=NO test

macos-local-app: ## Build the locally ad-hoc-signed macOS UI shell
	./scripts/build-local-app.sh

macos-run-local: ## Open the locally built macOS UI shell
	open .build/local/Wantastic.app

vet: vet-cli ## Vet portable Go packages

vet-cli: ## Vet CLI and platform-independent packages
	CGO_ENABLED=0 $(GO) vet -tags nosystray ./cmd/... ./internal/... ./pkg/...

check: test vet-cli install-check ## Run Go and Swift migration quality gates
	@git diff --check

audit: ## Scan the built CLI for reachable Go vulnerabilities
	@mkdir -p "$(BIN_DIR)"
	CGO_ENABLED=0 $(GO) build -trimpath -tags nosystray -o "$(BIN_DIR)/$(CLI_NAME)-audit" $(CLI_PACKAGE)
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest -mode=binary "$(BIN_DIR)/$(CLI_NAME)-audit"

install-check: ## Validate maintained installer scripts
	sh -n install.sh internal/update/self-update.sh e2e/run_p2p_test.sh e2e/docker-compose/entrypoint.sh

version: ## Print build identity
	@printf 'version=%s commit=%s date=%s\n' "$(VERSION)" "$(COMMIT)" "$(BUILD_DATE)"

clean: ## Remove local build outputs only
	$(GO) clean
	@test -n "$(BIN_DIR)" && test "$(BIN_DIR)" != / && rm -rf -- "$(BIN_DIR)"
