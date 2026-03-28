#!/bin/bash
# compile.sh — build srvguard binary
#
# Usage:
#   ./compile.sh           — build for current platform
#   ./compile.sh all       — build for all supported platforms (amd64, arm64)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="${SCRIPT_DIR}/src"
BIN_DIR="${SCRIPT_DIR}/bin"

build_target()
{
  local arch="$1"
  local out="$2"

  printf "Building %s ...\n" "${out}"
  ( cd "${SRC_DIR}" && CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
      go build -buildvcs=false -ldflags="-s -w" -o "${out}" . )
}

TARGET="${1:-native}"

case "${TARGET}" in
  native)
    NATIVE_ARCH=$(go env GOARCH)
    build_target "${NATIVE_ARCH}" "${BIN_DIR}/srvguard"
    ;;
  all)
    build_target amd64 "${BIN_DIR}/srvguard-linux-amd64"
    build_target arm64 "${BIN_DIR}/srvguard-linux-arm64"
    ;;
  amd64|arm64)
    build_target "${TARGET}" "${BIN_DIR}/srvguard-linux-${TARGET}"
    ;;
  *)
    printf "Usage: %s [all|amd64|arm64]\n" "$0"
    exit 1
    ;;
esac

printf "Done.\n"
