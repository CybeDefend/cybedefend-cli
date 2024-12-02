#!/bin/bash
# scripts/build-all.sh

set -e

APP_NAME="cybedefend"
OUTPUT_DIR="dist"
PLATFORMS=("windows/amd64" "windows/386" "linux/amd64" "linux/386" "darwin/amd64" "darwin/arm64")

echo "Building ${APP_NAME} for multiple platforms..."

mkdir -p "${OUTPUT_DIR}"

for PLATFORM in "${PLATFORMS[@]}"; do
    GOOS=${PLATFORM%%/*}
    GOARCH=${PLATFORM##*/}
    OUTPUT_NAME="${APP_NAME}-${GOOS}-${GOARCH}"
    if [ "${GOOS}" = "windows" ]; then
        OUTPUT_NAME+=".exe"
    fi
    echo "Building for ${GOOS}/${GOARCH}..."
    BUILD_PATH="${OUTPUT_DIR}/${OUTPUT_NAME}"
    env GOOS=${GOOS} GOARCH=${GOARCH} CGO_ENABLED=0 go build -ldflags "-s -w" -o "${BUILD_PATH}" .
done

echo "All builds completed successfully."
