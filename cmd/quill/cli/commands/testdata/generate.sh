#!/usr/bin/env bash
set -euo pipefail

# Build a minimal macOS binary for testing notarization
# This script is called by `go generate` from test_notarize.go

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(dirname "$SCRIPT_DIR")"
OUTPUT_FILE="$OUTPUT_DIR/test_notarize_hello.macho"

echo "Building test hello world binary..."

# Build for darwin/arm64 (Apple Silicon)
cd "$SCRIPT_DIR/hello"
GOOS=darwin GOARCH=arm64 go build -o "$OUTPUT_FILE" -ldflags="-s -w" .

echo "Generated test_notarize_hello.macho ($(wc -c < "$OUTPUT_FILE") bytes)"
