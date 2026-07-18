# Makefile for wantasticd

# Go parameters
GOCMD=go
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE?=$(shell date -u +'%Y-%m-%dT%H:%M:%SZ')
LDFLAGS="-s -w -X wantastic-agent/pkg/version.Version=$(VERSION) -X wantastic-agent/pkg/version.Commit=$(COMMIT) -X wantastic-agent/pkg/version.BuildDate=$(DATE)"
GOBUILD=$(GOCMD) build -ldflags=$(LDFLAGS)
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
BINARY_NAME=wantasticd
COMPRESS=upx -9 -v
CMD_PATH=./cmd/wantasticd

# Live RM520N-GL/WUSP diagnostics over ADB. Override ADB_GOARCH, ADB_SERIAL,
# ADB_REMOTE_DIR and ADB_TEST_ARGS for the target device.
ADB_GOOS?=linux
ADB_GOARCH?=arm64
ADB_GOARM?=7
ADB_TEST_BINARY=bin/wusp-device-test
ADB_AGENT_GOARCH?=arm
ADB_AGENT_GOARM?=7
ADB_AGENT_BINARY=bin/wantasticd-linux-$(ADB_AGENT_GOARCH)
ADB_AGENT_REMOTE_PATH?=/usr/bin/wantasticd
ADB_AGENT_SERVICE?=wantasticd

# Build targets
TARGETS := \
	darwin/arm64 \
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

# Demo server parameters
DEMO_BINARY_NAME=demoserver
DEMO_CMD_PATH=./cmd/demoserver

all: build

build:
	$(GOBUILD) -o bin/$(BINARY_NAME) $(CMD_PATH)

build-all:
	@for target in $(TARGETS); do \
		echo "Building for $$target"; \
		mkdir -p bin; \
		GOOS=$$(echo $$target | cut -d'/' -f1) GOARCH=$$(echo $$target | cut -d'/' -f2) $(GOBUILD) -o bin/$(BINARY_NAME)-$$(echo $$target | cut -d'/' -f1)-$$(echo $$target | cut -d'/' -f2) $(CMD_PATH); \
		$(COMPRESS) bin/$(BINARY_NAME)-$$(echo $$target | cut -d'/' -f1)-$$(echo $$target | cut -d'/' -f2); \
	done
	@echo "Building for linux/armv7"
	@mkdir -p bin
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o bin/$(BINARY_NAME)-linux-armv7 $(CMD_PATH)

# Build with native libiwinfo support (for OpenWrt/QSDK devices)
GOBUILD_IWINFO=CGO_ENABLED=1 $(GOCMD) build -tags iwinfo -ldflags=$(LDFLAGS)

build-iwinfo:
	$(GOBUILD_IWINFO) -o bin/$(BINARY_NAME)-iwinfo $(CMD_PATH)

# Linux iwinfo targets for embedded devices
IWINFO_TARGETS := linux/amd64 linux/arm64 linux/arm linux/mips linux/mipsle linux/mips64

build-all-iwinfo:
	@for target in $(IWINFO_TARGETS); do \
		echo "Building iwinfo for $$target"; \
		mkdir -p bin; \
		GOOS=$$(echo $$target | cut -d'/' -f1) GOARCH=$$(echo $$target | cut -d'/' -f2) $(GOBUILD_IWINFO) -o bin/$(BINARY_NAME)-$$(echo $$target | cut -d'/' -f1)-$$(echo $$target | cut -d'/' -f2)-iwinfo $(CMD_PATH); \
	done

build-%:
	@echo "Building for $*"
	@mkdir -p bin
	$(eval GOOS := $(word 1, $(subst /, ,$*)))
	$(eval GOARCH := $(word 2, $(subst /, ,$*)))
	GOOS=$(GOOS) GOARCH=$(GOARCH) $(GOBUILD) -o bin/$(BINARY_NAME)-$(GOOS)-$(GOARCH) $(CMD_PATH)



clean:
	$(GOCLEAN)
	rm -rf bin

run:
	$(GOBUILD) -o bin/$(BINARY_NAME) $(CMD_PATH)
	./bin/$(BINARY_NAME) connect -config traditional_wg.conf -v

# Demo server targets
build-demo:
	$(GOBUILD) -o bin/$(DEMO_BINARY_NAME) $(DEMO_CMD_PATH)

run-demo:
	$(GOBUILD) -o bin/$(DEMO_BINARY_NAME) $(DEMO_CMD_PATH)
	./bin/$(DEMO_BINARY_NAME)

release:
# create tag with release action first arg and push it
	git tag -a $(firstword $(filter-out release,$(MAKECMDGOALS))) -m "Release $(firstword $(filter-out release,$(MAKECMDGOALS)))"
	git push origin $(firstword $(filter-out release,$(MAKECMDGOALS)))
test:
	$(GOTEST) -v ./...

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

# Build and atomically replace the real agent on the connected device. The
# updater keeps a backup and restores it automatically if the service fails.
adb-wantasticd-update: adb-wantasticd-build
	@ADB_BINARY=$(ADB_AGENT_BINARY) ADB_REMOTE_PATH=$(ADB_AGENT_REMOTE_PATH) ADB_SERVICE=$(ADB_AGENT_SERVICE) tools/adb-update-wantasticd.sh

adb-wantasticd: adb-wantasticd-update

.PHONY: all build build-all build-iwinfo build-all-iwinfo clean run test genproto adb-test-build adb-test-run adb-live adb-wantasticd-build adb-wantasticd-update adb-wantasticd
