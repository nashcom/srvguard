# srvguard — Nash!Com Service Guard
#
# Build targets:
#   test    — Wolfi runtime, dynamically linked, for development and testing
#   release — Chainguard static runtime, fully static binary, production target
#
# Usage:
#   docker build --target test    -t srvguard:test .
#   docker build --target release -t srvguard:latest .  (default)

# -----------------------------------------------------------------------------
# Stage 1 — builder (shared)
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /build

COPY src/go.mod .
COPY src/*.go ./

# static binary — CGO not required, works for both targets
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o srvguard .

# -----------------------------------------------------------------------------
# Stage 2a — test (Wolfi runtime, non-static)
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/wolfi-base:latest AS test

RUN apk add --no-cache ca-certificates

RUN adduser -D -u 1000 srvguard

COPY --from=builder /build/srvguard /usr/local/bin/srvguard

RUN mkdir -p /etc/srvguard /run/srvguard/certs && \
    chown srvguard:srvguard /etc/srvguard /run/srvguard/certs

USER 1000

ENTRYPOINT ["/usr/local/bin/srvguard"]

# -----------------------------------------------------------------------------
# Stage 2b — release (Chainguard static, production)
# -----------------------------------------------------------------------------
FROM cgr.dev/chainguard/static:latest AS release

COPY --from=builder /build/srvguard /usr/local/bin/srvguard

# Chainguard static runs as nonroot (uid 65532) by default
USER 65532

ENTRYPOINT ["/usr/local/bin/srvguard"]
