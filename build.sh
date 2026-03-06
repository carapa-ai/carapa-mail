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

IMAGE="carapamail:latest"

echo ""
echo "Building $IMAGE...${BUILD_ARGS:+ (no cache)}"
docker build $BUILD_ARGS -t "$IMAGE" .

# Pull third-party images if not present
for DEP_IMAGE in postgres:17-alpine djmaze/snappymail:latest; do
    if ! docker image inspect "$DEP_IMAGE" >/dev/null 2>&1; then
        echo ""
        echo "Pulling $DEP_IMAGE..."
        docker pull "$DEP_IMAGE"
    fi
done

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

scan_image "$IMAGE"
scan_image "postgres:17-alpine"
scan_image "djmaze/snappymail:latest"

echo ""
echo "Done."
