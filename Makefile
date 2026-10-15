GOCMD=go
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE?=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
MACOSX_DEPLOYMENT_TARGET?=13.0
LDFLAGS=-s -w -X wantastic-agent/pkg/version.Version=$(VERSION) -X wantastic-agent/pkg/version.Commit=$(COMMIT) -X wantastic-agent/pkg/version.BuildDate=$(DATE)
DESKTOP_LDFLAGS=$(LDFLAGS)
ifeq ($(shell uname -s),Darwin)
DESKTOP_LDFLAGS+=-extldflags=-mmacosx-version-min=$(MACOSX_DEPLOYMENT_TARGET)
endif
GOBUILD=$(GOCMD) build -ldflags="$(LDFLAGS)"
BINARY_NAME=wantasticd
CMD_PATH=./cmd/wantasticd

ADB_GOOS?=linux
ADB_GOARCH?=arm
ADB_GOARM?=7
ADB_TEST_BINARY=bin/wusp-device-test
ADB_AGENT_GOARCH?=arm
ADB_AGENT_GOARM?=7
ADB_AGENT_BINARY=bin/wantasticd-linux-$(ADB_AGENT_GOARCH)
ADB_AGENT_REMOTE_PATH?=/usr/bin/wantasticd
ADB_AGENT_SERVICE?=wantasticd
ADB_AGENT_CONFIG_PATH?=/etc/wantastic

TARGETS := darwin/arm64 linux/386 linux/amd64 linux/arm linux/arm64 linux/loong64 \
	linux/mips linux/mips64 linux/mips64le linux/mipsle linux/ppc64 linux/ppc64le \
	linux/riscv64 linux/s390x windows/amd64

all: build

build:
	@mkdir -p bin
	$(GOBUILD) -o bin/$(BINARY_NAME) $(CMD_PATH)

desktop:
	go run github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-beta.29 task package WANTASTIC_LDFLAGS='$(DESKTOP_LDFLAGS)'

desktop-dev:
	go run github.com/wailsapp/wails/v3/cmd/wails3@v3.0.0-beta.29 dev -config ./build/config.yml

build-all:
	@for target in $(TARGETS); do \
		echo "Building for $$target"; \
		mkdir -p bin; \
		GOOS=$$(echo $$target | cut -d'/' -f1) GOARCH=$$(echo $$target | cut -d'/' -f2) CGO_ENABLED=0 \
			$(GOCMD) build -tags nosystray -ldflags="$(LDFLAGS)" \
			-o bin/$(BINARY_NAME)-$$(echo $$target | tr '/' '-') $(CMD_PATH); \
	done
	@mkdir -p bin
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 $(GOCMD) build -tags nosystray -ldflags="$(LDFLAGS)" -o bin/$(BINARY_NAME)-linux-armv7 $(CMD_PATH)

GOBUILD_IWINFO=CGO_ENABLED=1 $(GOCMD) build -tags iwinfo -ldflags="$(LDFLAGS)"
build-iwinfo:
	@mkdir -p bin
	$(GOBUILD_IWINFO) -o bin/$(BINARY_NAME)-iwinfo $(CMD_PATH)

test:
	$(GOCMD) test -tags nosystray ./...

clean:
	$(GOCMD) clean
	rm -rf bin build/bin

run: build
	./bin/$(BINARY_NAME) connect -config traditional_wg.conf -v

release:
	git tag -a $(firstword $(filter-out release,$(MAKECMDGOALS))) -m "Release $(firstword $(filter-out release,$(MAKECMDGOALS)))"
	git push origin $(firstword $(filter-out release,$(MAKECMDGOALS)))

adb-test-build:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=$(ADB_GOOS) GOARCH=$(ADB_GOARCH) GOARM=$(ADB_GOARM) $(GOCMD) build -trimpath -o $(ADB_TEST_BINARY) ./cmd/test

adb-test-run: adb-test-build
	@ADB_LIVE_ONCE=1 ADB_BINARY=$(ADB_TEST_BINARY) ADB_TEST_ARGS='$(ADB_TEST_ARGS)' tools/adb-live.sh

adb-live:
	@ADB_BINARY=$(ADB_TEST_BINARY) ADB_TEST_ARGS='$(ADB_TEST_ARGS)' tools/adb-live.sh

adb-wantasticd-build:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ADB_AGENT_GOARCH) GOARM=$(ADB_AGENT_GOARM) $(GOBUILD) -trimpath -o $(ADB_AGENT_BINARY) $(CMD_PATH)

adb-wantasticd-update: adb-wantasticd-build
	@ADB_BINARY=$(ADB_AGENT_BINARY) ADB_REMOTE_PATH=$(ADB_AGENT_REMOTE_PATH) ADB_SERVICE=$(ADB_AGENT_SERVICE) ADB_CONFIG_PATH=$(ADB_AGENT_CONFIG_PATH) tools/adb-update-wantasticd.sh

adb-wantasticd: adb-wantasticd-update

.PHONY: all build desktop desktop-dev build-all build-iwinfo test clean run release \
	adb-test-build adb-test-run adb-live adb-wantasticd-build adb-wantasticd-update adb-wantasticd
