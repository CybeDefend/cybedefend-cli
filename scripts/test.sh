#!/bin/bash
# scripts/test.sh

set -e

echo "Running tests..."

go test ./... "$@"

echo "Tests completed."
