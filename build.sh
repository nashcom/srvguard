#!/bin/bash
# build.sh — build the srvguard container image
#
# Usage:
#   ./build.sh              — build release image for local platform (--load)
#   ./build.sh test         — build test image for local platform (--load)
#   ./build.sh release      — build release image for local platform (--load)
#   ./build.sh both         — build both targets for local platform (--load)
#   ./build.sh push         — build multi-arch release and push to registry
#
# Multi-arch (linux/amd64 + linux/arm64) requires --push to a registry.
# Use REGISTRY=myregistry.example.com/srvguard ./build.sh push

IMAGE_NAME="${REGISTRY:-srvguard}"
IMAGE_TAG="0.9.0"
PLATFORMS="linux/amd64,linux/arm64"
LOCAL_PLATFORM="linux/$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
TARGET="${1:-release}"

build_target()
{
    local target="$1"
    local tag_suffix="$2"
    local platforms="$3"
    local output="$4"   # --load or --push

    printf "Building %s:%s (%s) [%s] %s\n" \
        "${IMAGE_NAME}" "${IMAGE_TAG}" "${target}" "${platforms}" "${output}"

    docker buildx build \
        --platform "${platforms}" \
        --target "${target}" \
        --tag "${IMAGE_NAME}:${tag_suffix}" \
        --tag "${IMAGE_NAME}:${tag_suffix}-${IMAGE_TAG}" \
        "${output}" \
        .
}

case "${TARGET}" in
    test)
        build_target test test "${LOCAL_PLATFORM}" --load
        ;;
    release)
        build_target release latest "${LOCAL_PLATFORM}" --load
        ;;
    both)
        build_target test    test   "${LOCAL_PLATFORM}" --load
        build_target release latest "${LOCAL_PLATFORM}" --load
        ;;
    push)
        [[ -n "${REGISTRY:-}" ]] || \
            { printf "Set REGISTRY=host/repo before pushing\n"; exit 1; }
        build_target release latest "${PLATFORMS}" --push
        ;;
    *)
        printf "Usage: %s [test|release|both|push]\n" "$0"
        exit 1
        ;;
esac

printf "Done.\n"
