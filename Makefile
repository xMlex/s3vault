BINARY_NAME=s3vault
GO=go
GOFLAGS=-v
VERSION?=$(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS=-ldflags "-X main.version=$(VERSION)"

.PHONY: all build clean test lint fmt e2e e2e-up e2e-down e2e-clean \
	verify verify-detect verify-layers verify-drift

all: test build

# VCS-стампинг не нужен: версия приходит из ldflags, а VERSION уже умеет
# fallback на dev без git. -buildvcs=false даёт сборку в окружениях, где git
# недоступен или репозиторий помечен dubious ownership.
build:
	CGO_ENABLED=0 $(GO) build -buildvcs=false $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME) ./cmd/s3vault

clean:
	rm -rf bin/ coverage.out coverage.html $(BINARY_NAME)

test:
	$(GO) test -race -count=1 ./...

lint:
	golangci-lint run ./...

fmt:
	gofumpt -w .
	goimports -w .

# Стенды детектора шифрования. Нужен живой MinIO на 127.0.0.1:9000 и бакет
# s3vault: make e2e-up поднимает и создаёт. Каждый стенд возвращает ненулевой
# код при нарушении контракта, так что цель годится и как CI-шаг.
#
# Подробности — docs/decrypt-detection.md.
verify: verify-detect verify-layers verify-drift

verify-detect:
	./scripts/verify-decrypt-detection.sh

verify-layers:
	./scripts/verify-layer-ownership.sh

verify-drift:
	./scripts/verify-server-drift.sh

# Полный e2e против живого MinIO из compose.e2e.yaml.
e2e:
	./scripts/e2e.sh

e2e-up:
	./scripts/e2e.sh up

e2e-down:
	./scripts/e2e.sh down

e2e-clean:
	./scripts/e2e.sh clean
