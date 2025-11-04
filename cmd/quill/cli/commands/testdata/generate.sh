#!/usr/bin/env bash
set -euo pipefail

# Build a minimal macOS binary for testing notarization
# This script is called by `go generate` from test_notarize.go

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Building test hello world binary..."

# Build for darwin/arm64 (Apple Silicon)
cd "$SCRIPT_DIR/hello"
GOOS=darwin GOARCH=arm64 go build -o "$SCRIPT_DIR/hello.macho" -ldflags="-s -w" .

echo "Base64 encoding binary..."
base64 < "$SCRIPT_DIR/hello.macho" > "$OUTPUT_DIR/test_notarize_hello.b64"

# Clean up the binary
rm "$SCRIPT_DIR/hello.macho"

echo "Generated test_notarize_hello.b64 ($(wc -c < "$OUTPUT_DIR/test_notarize_hello.b64") bytes)"
