#!/bin/bash
# build.sh — build the srvguard container image
#
# Usage:
#   ./build.sh              — build release image, multi-arch (amd64 + arm64)
#   ./build.sh test         — build test image (Wolfi runtime), local platform only
#   ./build.sh release      — build release image (Chainguard static), multi-arch
#   ./build.sh both         — build both targets, multi-arch

IMAGE_NAME="srvguard"
IMAGE_TAG="0.9.0"
PLATFORMS="linux/amd64,linux/arm64"
TARGET="${1:-release}"

build_target()
{
  local target="$1"
  local tag_suffix="$2"
  local platforms="$3"

  printf "Building %s:%s (%s) [%s]\n" "${IMAGE_NAME}" "${IMAGE_TAG}" "${target}" "${platforms}"

  docker buildx build \
    --platform "${platforms}" \
    --target "${target}" \
    --tag "${IMAGE_NAME}:${tag_suffix}" \
    --tag "${IMAGE_NAME}:${tag_suffix}-${IMAGE_TAG}" \
    --load \
    .
}

case "${TARGET}" in
  test)
    build_target test test "linux/amd64,linux/arm64"
    ;;
  release)
    build_target release latest "${PLATFORMS}"
    ;;
  both)
    build_target test test "${PLATFORMS}"
    build_target release latest "${PLATFORMS}"
    ;;
  *)
    printf "Usage: %s [test|release|both]\n" "$0"
    exit 1
    ;;
esac

printf "Done.\n"
