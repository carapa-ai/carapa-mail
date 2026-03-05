#!/bin/bash
# ── CarapaMail — Build & CVE Scan ─────────────────────────────────
# Builds the carapamail image and scans it for known CVEs.
# Exit code is always 0 (advisory only).
set -e

echo "══════════════════════════════════════════════════════════"
echo "  Carapa-Mail — Build & CVE Scan"
echo "══════════════════════════════════════════════════════════"

BUILD_ARGS=""
if [[ "${1:-}" == "--no-cache" ]]; then
    BUILD_ARGS="--no-cache"
    shift
fi

IMAGE="carapamail:latest"

echo ""
echo "Building $IMAGE...${BUILD_ARGS:+ (no cache)}"
docker build $BUILD_ARGS -t "$IMAGE" .

echo ""
echo "Scanning $IMAGE for CVEs..."
if command -v docker &>/dev/null && docker scout version &>/dev/null 2>&1; then
    docker scout cves "$IMAGE" --only-severity critical,high 2>/dev/null || true
elif command -v trivy &>/dev/null; then
    trivy image "$IMAGE" --severity CRITICAL,HIGH 2>/dev/null || true
else
    echo "  (no CVE scanner found — install docker scout or trivy)"
fi
