#!/bin/bash
# scripts/run.sh

set -e

echo "Running cybedefend..."

CGO_ENABLED=0 go run main.go "$@"
