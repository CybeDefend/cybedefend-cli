#!/bin/bash
# scripts/clean.sh

set -e

OUTPUT_DIR="dist"

echo "Cleaning build artifacts..."

rm -rf "${OUTPUT_DIR}"

echo "Clean completed."
