# syntax=docker/dockerfile:1.7

# yalla-api production container — multi-stage, least-privilege, no baked secrets.
#
# Stages
# ------
#   1. builder — pinned golang toolchain, static cgo-disabled build with version
#      metadata injected via -ldflags so GET /version surfaces what shipped.
#   2. runtime — distroless static-debian12:nonroot. UID/GID 65532, no shell, no
#      package manager, only the API binary and a CA bundle. Defence-in-depth
#      even if the application later mishandles a path.
#
# Build
# -----
#   docker build \
#     --build-arg VERSION="$(git describe --tags --always)" \
#     --build-arg COMMIT="$(git rev-parse HEAD)" \
#     --build-arg DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
#     -t yalla-api:dev \
#     -f Dockerfile .
#
# Run
# ---
# Secrets are supplied by the operator at runtime through environment variables.
# They are NEVER baked into the image — a leaked image must not leak production
# credentials. Read-only root filesystem + dropped capabilities are recommended:
#
#   docker run --rm --read-only --cap-drop=ALL \
#     -e YALLA_PROFILE=production \
#     -e YALLA_API_ADDR=0.0.0.0:8080 \
#     -e YALLA_PUBLIC_URL=https://api.example.com \
#     -e YALLA_DATABASE_URL=... \
#     -e YALLA_SIGNING_KEYS=... \
#     -e YALLA_DOKPLOY_BASE_URL=... \
#     -e YALLA_DOKPLOY_TOKEN=... \
#     -p 8080:8080 yalla-api:dev
#
# Health / readiness
# ------------------
# The container exposes :8080. Orchestrators should probe the API directly:
#   - Liveness:  GET /healthz  -> 200 with {"status":"ok"} when the process is up.
#   - Readiness: GET /readyz   -> 200 only when every startup dependency is green;
#                                 503 with the failing gate name otherwise.
# HEALTHCHECK is intentionally omitted because the distroless runtime has no shell
# or curl binary. Kubernetes/Nomad/ECS/Docker Compose probe the endpoints over
# HTTP without needing an in-image helper.
#
# Logs
# ----
# yalla-api writes structured JSON to stdout, one record per line. Every record
# carries service=yalla-api. The DSN, signing keys, and Dokploy token are
# redacted at the structured-logging layer and never appear in logs.

ARG GO_VERSION=1.23
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

FROM golang:${GO_VERSION}-bookworm AS builder

ARG VERSION=0.0.0-dev
ARG COMMIT=unknown
ARG DATE=unknown

WORKDIR /src

# Cache modules separately so a source-only change does not reseed the
# dependency layer.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download

COPY . .

# CGO_ENABLED=0 produces a static binary suitable for the distroless static
# image. -trimpath strips local filesystem paths from the binary so a leaked
# binary does not reveal the build host's directory layout. -s -w drops the
# symbol and DWARF tables to shrink the binary. -ldflags injects build metadata
# that GET /version surfaces.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux \
    go build \
      -trimpath \
      -ldflags="-s -w \
        -X main.Version=${VERSION} \
        -X main.Commit=${COMMIT} \
        -X main.Date=${DATE}" \
      -o /out/yalla-api \
      ./cmd/yalla-api

FROM ${RUNTIME_IMAGE}

# Distroless nonroot is UID 65532 / GID 65532. The image runs no privileged
# code and the root filesystem is meant to be mounted read-only at runtime.
USER nonroot:nonroot

WORKDIR /app

COPY --from=builder --chown=nonroot:nonroot /out/yalla-api /usr/local/bin/yalla-api

# Document the listen port. The production / staging profile defaults to :8080
# in internal/controlplane/config/load.go; keep this hint in sync with that
# default so docker port mappings line up with the binary's listen address.
EXPOSE 8080

# OCI labels record provenance without baking it into the binary. The same
# values are also baked into the binary via -ldflags above and surface through
# GET /version.
ARG VERSION
ARG COMMIT
ARG DATE
LABEL org.opencontainers.image.title="yalla-api" \
      org.opencontainers.image.description="Yalla Control Plane HTTP API" \
      org.opencontainers.image.source="https://github.com/JuribaDev/yalla" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.created="${DATE}" \
      org.opencontainers.image.licenses="Proprietary"

ENTRYPOINT ["/usr/local/bin/yalla-api"]
