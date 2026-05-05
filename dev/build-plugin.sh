#!/usr/bin/env bash
# Build overlay_plugin.so in the build-vpp-overlay-dev:latest container
# and extract it to ./artifacts/overlay_plugin.so on the host.
#
# Usage: bash dev/build-plugin.sh
#
# Mac can't build VPP natively; the container runs x86_64 under qemu.
# Build takes ~5-10 min the first time, faster with ccache on subsequent runs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_SRC="$REPO_ROOT/src/plugins/overlay"
DEV_DIR="$REPO_ROOT/dev"
OUT_DIR="$DEV_DIR/artifacts"
IMAGE="build-vpp-overlay-dev:latest"

mkdir -p "$OUT_DIR"

if ! docker image inspect "$IMAGE" >/dev/null 2>&1 \
   && ! docker images --format '{{.Repository}}:{{.Tag}}' "$IMAGE" 2>/dev/null \
        | grep -qx "$IMAGE"; then
  echo "ERROR: image $IMAGE not found. Run dev/build-image.sh first." >&2
  exit 1
fi

echo "=== Building overlay_plugin.so in $IMAGE ==="
docker run --rm --platform linux/amd64 \
  -v "$PLUGIN_SRC":/plugin/overlay:ro \
  -v "$DEV_DIR":/dev-wrapper:ro \
  -v "$OUT_DIR":/out \
  "$IMAGE" bash -c '
    set -euo pipefail
    mkdir -p /build && cd /build
    cmake /dev-wrapper \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DVPP_LIBRARY_DIR=/usr/lib/x86_64-linux-gnu \
      2>&1 | tail -5
    mkdir -p CMakeFiles/vpp-api/vapi
    make -j"$(nproc)" 2>&1 | grep -E "(Linking|error:)" || true
    make install 2>&1 | grep "Installing.*overlay" || true
    cp /usr/lib/x86_64-linux-gnu/vpp_plugins/overlay_plugin.so /out/
    sha256sum /out/overlay_plugin.so
  '

echo
echo "=== Done ==="
ls -lh "$OUT_DIR/overlay_plugin.so"
sha256sum "$OUT_DIR/overlay_plugin.so"
