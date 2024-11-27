#!/bin/bash
# scripts/fmt.sh

set -e

echo "Formatting code..."

go fmt ./...

echo "Formatting completed."
