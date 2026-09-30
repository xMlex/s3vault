# syntax=docker/dockerfile:1

# Version is injected the same way the Makefile and GoReleaser do it, not by
# VCS stamping: the build must work in environments without git.
#   docker build --build-arg VERSION=1.2.3 -t s3vault:1.2.3 .
ARG GO_VERSION=1.26
ARG VERSION=dev

FROM golang:${GO_VERSION}-alpine AS build
ARG VERSION
WORKDIR /src

# go.mod/go.sum first: dependency layer is reused until they actually change.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 -> no libc, runs on scratch/distroless. -trimpath drops local
# paths so the binary does not leak the build directory.
RUN CGO_ENABLED=0 go build -buildvcs=false -trimpath \
      -ldflags "-s -w -X main.version=${VERSION}" \
      -o /out/s3vault ./cmd/s3vault \
    && /out/s3vault version

# cache.dir defaults to os.UserCacheDir()/s3vault, which is under the home of
# whatever user we run as. Create it here, as root, so the nonroot user of the
# final image can actually write into it. Mount a volume on /cache to keep
# plaintext between runs (see the security note in README.md).
RUN mkdir -p /cache

FROM gcr.io/distroless/static-debian12:nonroot AS runtime

COPY --from=build /out/s3vault /usr/local/bin/s3vault
COPY --from=build /cache /cache

ENV HOME=/cache
# Not secrets — these are the config entrypoints an operator sets per deploy.
ENV S3VAULT_CACHE_DIR=/cache
# Default listen is 127.0.0.1, which is unreachable from outside the container.
# Serving from the image therefore needs an explicit bind address and the S3
# facade key pair: without it the server is refused at startup (ErrS3CredsRequired).
#   docker run -e S3VAULT_SERVER_LISTEN=0.0.0.0:8080 \
#     -e S3VAULT_SERVER_S3_ACCESS_KEY=vaultak -e S3VAULT_SERVER_S3_SECRET_KEY=vaultsk \
#     -p 8080:8080 s3vault server
ENV S3VAULT_SERVER_LISTEN=0.0.0.0:8080

# 8080: HTTP server, 9090: metrics (server.metrics_listen).
EXPOSE 8080 9090

# distroless has no shell and no cryptcp, so `encryption.mode=command` cannot
# work from this image — that mode execs an external CryptoPro tool. Use
# `encryption.mode=native`, or build on a base that carries cryptcp.
ENTRYPOINT ["/usr/local/bin/s3vault"]
CMD ["--help"]
