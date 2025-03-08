#!/bin/bash
# scripts/run.sh

set -e

echo "Running cybedefend..."

go run main.go "$@"
