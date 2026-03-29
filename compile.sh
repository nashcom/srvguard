#!/bin/sh
# compile.sh — build srvguard binary
#
# Usage:
#   ./compile.sh              — build for current platform (requires Go)
#   ./compile.sh -all         — build amd64 + arm64 (requires Go)
#   ./compile.sh -amd64       — build linux/amd64 (requires Go)
#   ./compile.sh -arm64       — build linux/arm64 (requires Go)
#   ./compile.sh -docker      — build for current platform inside golang:alpine

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Ensure git uses the shared hooks directory so .sh files are kept executable.
git config core.hooksPath .githooks 2>/dev/null || true
SRC_DIR="${SCRIPT_DIR}/src"
BIN_DIR="${SCRIPT_DIR}/bin"

GO_IMAGE="${GO_IMAGE:-golang:alpine}"

usage() { printf "Usage: %s [-docker|-all|-amd64|-arm64]\n" "$0"; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────

OPT_DOCKER=false
OPT_ALL=false
OPT_ARCH=""

for arg in "$@"; do
    case "$arg" in
        -docker) OPT_DOCKER=true ;;
        -all)    OPT_ALL=true    ;;
        -amd64)  OPT_ARCH=amd64  ;;
        -arm64)  OPT_ARCH=arm64  ;;
        *)       usage            ;;
    esac
done

# ── Docker mode ───────────────────────────────────────────────────────────────

if $OPT_DOCKER; then
    command -v docker &>/dev/null || { printf "ERROR: docker not found\n" >&2; exit 1; }
    printf "Building inside container (%s) → bin/srvguard ...\n" "${GO_IMAGE}"
    docker run --rm \
        -v "${SCRIPT_DIR}:/work" \
        -w /work \
        "${GO_IMAGE}" \
        sh -c "sh compile.sh"
    exit $?
fi

# ── Native build ──────────────────────────────────────────────────────────────

build_target()
{
    local arch="$1"
    local out="$2"
    local ldflags="-s -w"

    # Inject shared secret at build time when SRVGUARD_BUILD_SALT is set.
    # Both srvguard (Go) and domsrvguard (C++) must be built with the same value.
    # Generate a value: od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
    if [ -n "${SRVGUARD_BUILD_SALT:-}" ]; then
        ldflags="${ldflags} -X 'main.keyringBuildSalt=${SRVGUARD_BUILD_SALT}'"
    fi

    printf "Building %s ...\n" "${out}"
    ( cd "${SRC_DIR}" && CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
        go build -buildvcs=false -ldflags="${ldflags}" -o "${out}" . )
}

if $OPT_ALL; then
    build_target amd64 "${BIN_DIR}/srvguard-linux-amd64"
    build_target arm64 "${BIN_DIR}/srvguard-linux-arm64"
elif [ -n "$OPT_ARCH" ]; then
    build_target "${OPT_ARCH}" "${BIN_DIR}/srvguard-linux-${OPT_ARCH}"
else
    NATIVE_ARCH=$(go env GOARCH)
    build_target "${NATIVE_ARCH}" "${BIN_DIR}/srvguard"
fi

printf "Done.\n"
