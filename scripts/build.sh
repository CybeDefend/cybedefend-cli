#!/bin/bash
# scripts/build.sh

set -e

APP_NAME="cybedefend"
OUTPUT_DIR="dist"

echo "Building ${APP_NAME} for the current platform..."

mkdir -p "${OUTPUT_DIR}"

GOOS=$(go env GOOS)
GOARCH=$(go env GOARCH)
CGO_ENABLED=0 go build -ldflags "-s -w" -o "${OUTPUT_DIR}/${APP_NAME}" .

echo "Build completed: ${OUTPUT_DIR}/${APP_NAME}"
