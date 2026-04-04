#!/usr/bin/env bash
# Build the DynamoRIO client inside Docker

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="dynamorio-sandbox-builder"

echo "[build.sh] Building Docker image..."
docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"

echo "[build.sh] Extracting built artifacts..."
# Run the container and copy out the .so
docker run --rm \
    -v "$SCRIPT_DIR:/output" \
    "$IMAGE_NAME" \
    bash -c "cp /sandbox/syscall_filter.so /output/ && cp /sandbox/test_open /output/ 2>/dev/null || true"

echo "[build.sh] Build complete: syscall_filter.so"
ls -lh "$SCRIPT_DIR/syscall_filter.so" 2>/dev/null || echo "(artifact not yet extracted - run docker manually)"
