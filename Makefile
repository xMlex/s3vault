BINARY_NAME=s3vault
GO=go
GOFLAGS=-v
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: all build clean test lint fmt

all: test build

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME) ./cmd/s3vault

clean:
	rm -rf bin/ coverage.out coverage.html

test:
	$(GO) test -race -count=1 ./...

lint:
	golangci-lint run ./...

fmt:
	gofumpt -w .
	goimports -w .
