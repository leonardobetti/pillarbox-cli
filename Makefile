BINARY  := pillarbox
BIN_DIR := bin
PKG     := ./cmd/pillarbox
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0)
LDFLAGS := -X github.com/leonardobetti/pillarbox-cli/internal/cli.Version=$(VERSION)

.PHONY: all build test lint

all: build

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(PKG)

test:
	go test ./...

lint:
	golangci-lint run
