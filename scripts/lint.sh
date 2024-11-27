#!/bin/bash
# scripts/lint.sh

set -e

echo "Linting code..."

if ! command -v golangci-lint &> /dev/null; then
    echo "golangci-lint not found. Installing..."
    go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
fi

golangci-lint run ./...

echo "Linting completed."
