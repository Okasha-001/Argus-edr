# ARGUS — eBPF EDR build orchestration.
# Two independent halves: the eBPF objects (clang) and the Go binaries (go).
# The agent loads the objects at runtime, so `make build` never needs clang.

SHELL := /usr/bin/env bash

GO      ?= go
CLANG   ?= clang
BPFTOOL ?= bpftool
STRIP   ?= llvm-strip

ARCH      := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
BUILD_DIR := build
BIN_DIR   := $(BUILD_DIR)/bin
BPF_DIR   := bpf
VMLINUX   := $(BPF_DIR)/vmlinux.h
BPF_SRCS  := $(wildcard $(BPF_DIR)/*.bpf.c)
BPF_OBJS  := $(patsubst $(BPF_DIR)/%.bpf.c,$(BUILD_DIR)/%.bpf.o,$(BPF_SRCS))
# The ABI (common.h) and shared bpf headers are prerequisites of every object, so
# a struct change rebuilds both the sensor and the LSM object — never just one.
BPF_HEADERS := $(filter-out $(VMLINUX),$(wildcard $(BPF_DIR)/*.h $(BPF_DIR)/headers/*.h))

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
# Package metadata: strip a leading v for semver (v1.2.3 -> 1.2.3) and use the
# Go arch name (amd64/arm64) the deb/rpm tooling expects.
PKG_VERSION := $(patsubst v%,%,$(VERSION))
NFPM_ARCH   := $(shell $(GO) env GOARCH)
PKG      := github.com/argus-edr/argus/internal/version
LDFLAGS  := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).BuildDate=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
              -Wall -Werror -Wno-unused-function -Wno-compare-distinct-pointer-types \
              -Wno-missing-declarations \
              -I$(BPF_DIR) -I$(BPF_DIR)/headers

.DEFAULT_GOAL := build

## help: list available targets
.PHONY: help
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /' | sort

## vmlinux: regenerate the CO-RE type header from the running kernel's BTF
.PHONY: vmlinux
vmlinux: $(VMLINUX)
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

## bpf: compile the eBPF sensors into CO-RE objects (needs clang + BTF)
.PHONY: bpf
bpf: $(BPF_OBJS)
$(BUILD_DIR)/%.bpf.o: $(BPF_DIR)/%.bpf.c $(VMLINUX) $(BPF_HEADERS)
	@mkdir -p $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@$(STRIP) -g $@ 2>/dev/null || true

## build: compile the agent and control-plane binaries
.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/argus ./cmd/argus
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN_DIR)/argus-server ./cmd/argus-server

## ui: validate the embedded web console assets (no Node; assets ship in-binary)
.PHONY: ui
ui:
	@test -f ui/static/index.html || { echo "ui/static/index.html missing"; exit 1; }
	$(GO) build ./ui
	@echo "web console assets OK (served by argus-server --ui-addr)"

## all: build both the eBPF objects and the Go binaries
.PHONY: all
all: bpf build

## generate: run code generators (none required for the runtime-loader path)
.PHONY: generate
generate:
	$(GO) generate ./...

## fmt: format Go and C sources
.PHONY: fmt
fmt:
	$(GO) fmt ./...
	@command -v clang-format >/dev/null 2>&1 && clang-format -i $(BPF_DIR)/*.c $(BPF_DIR)/*.h || true

## vet: run go vet
.PHONY: vet
vet:
	$(GO) vet ./...

## lint: run golangci-lint
.PHONY: lint
lint:
	golangci-lint run ./...

## test: run unit tests
.PHONY: test
test:
	$(GO) test ./...

## test-race: run unit tests with the race detector and coverage
.PHONY: test-race
test-race:
	$(GO) test -race -coverprofile=coverage.txt -covermode=atomic ./...

## cover: open the HTML coverage report
.PHONY: cover
cover: test-race
	$(GO) tool cover -html=coverage.txt -o coverage.html

## bench: run the hot-path benchmarks (decode, detection, pipeline)
.PHONY: bench
bench:
	$(GO) test -run='^$$' -bench=. -benchmem ./internal/decode ./internal/detect ./internal/pipeline

## fuzz: fuzz the untrusted-input parsers — FuzzDecode (./internal/decode), FuzzRuleCompile (./internal/detect), FuzzConvert (./internal/sigma); override: make fuzz FUZZ=FuzzConvert PKG=./internal/sigma SECS=30
FUZZ ?= FuzzRuleCompile
PKG  ?= ./internal/detect
SECS ?= 30
.PHONY: fuzz
fuzz:
	$(GO) test -run='^$$' -fuzz=$(FUZZ) -fuzztime=$(SECS)s $(PKG)

## tidy: sync go.mod/go.sum
.PHONY: tidy
tidy:
	$(GO) mod tidy

## run: build then run the agent against the example config (needs root for eBPF)
.PHONY: run
run: all
	sudo $(BIN_DIR)/argus run --config configs/argus.yaml

## replay: run the pipeline over a recorded event stream (no root, no kernel)
.PHONY: replay
replay: build
	$(BIN_DIR)/argus replay --rules rules test/integration/testdata/killchain.ndjson

## install: install binaries, objects, rules and config onto the host
.PHONY: install
install: all
	install -Dm0755 $(BIN_DIR)/argus /usr/local/bin/argus
	install -Dm0644 $(BUILD_DIR)/edr.bpf.o /usr/lib/argus/edr.bpf.o
	install -Dm0644 configs/argus.yaml /etc/argus/config.yaml
	cp -r rules /etc/argus/

## package: build signed-ready deb + rpm with nfpm (needs `make all` artifacts + nfpm)
DIST_DIR := $(BUILD_DIR)/dist
.PHONY: package
package: all
	@command -v nfpm >/dev/null 2>&1 || { echo "nfpm not found — https://nfpm.goreleaser.com/install/"; exit 1; }
	@mkdir -p $(DIST_DIR)
	VERSION=$(PKG_VERSION) NFPM_ARCH=$(NFPM_ARCH) nfpm package -f packaging/nfpm.yaml -p deb -t $(DIST_DIR)
	VERSION=$(PKG_VERSION) NFPM_ARCH=$(NFPM_ARCH) nfpm package -f packaging/nfpm.yaml -p rpm -t $(DIST_DIR)
	@ls -1 $(DIST_DIR)

## sbom: generate a CycloneDX SBOM of the source + dependencies with syft
.PHONY: sbom
sbom:
	@command -v syft >/dev/null 2>&1 || { echo "syft not found — https://github.com/anchore/syft"; exit 1; }
	@mkdir -p $(DIST_DIR)
	syft dir:. -o cyclonedx-json=$(DIST_DIR)/argus.sbom.cdx.json
	@echo "wrote $(DIST_DIR)/argus.sbom.cdx.json"

## verifier-smoke: load the compiled eBPF objects and confirm the verifier accepts them (needs root + a BTF kernel)
.PHONY: verifier-smoke
verifier-smoke: bpf
	./scripts/verifier-smoke.sh

## clean: remove build artifacts
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR) coverage.txt coverage.html
