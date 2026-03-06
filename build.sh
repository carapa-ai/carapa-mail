#!/bin/bash
# ── CarapaMail — Build & CVE Scan ─────────────────────────────────
# Builds the carapamail image and scans all images for known CVEs.
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

echo ""
echo "Building carapamail:latest...${BUILD_ARGS:+ (no cache)}"
docker build $BUILD_ARGS -t "carapamail:latest" .

echo ""
echo "Building snappymail:latest...${BUILD_ARGS:+ (no cache)}"
docker build $BUILD_ARGS -t "snappymail:latest" webmail/

# Pull third-party images if not present
if ! docker image inspect "postgres:17-alpine" >/dev/null 2>&1; then
    echo ""
    echo "Pulling postgres:17-alpine..."
    docker pull "postgres:17-alpine"
fi

# CVE scan
scan_image() {
    local img="$1"
    echo ""
    echo "Scanning $img for CVEs..."
    if command -v docker &>/dev/null && docker scout version &>/dev/null 2>&1; then
        docker scout cves "$img" --only-severity critical,high 2>/dev/null || true
    elif command -v trivy &>/dev/null; then
        trivy image "$img" --severity CRITICAL,HIGH 2>/dev/null || true
    else
        echo "  (no CVE scanner found — install docker scout or trivy)"
        return
    fi
}

scan_image "carapamail:latest"
scan_image "snappymail:latest"
scan_image "postgres:17-alpine"

echo ""
echo "Done."
