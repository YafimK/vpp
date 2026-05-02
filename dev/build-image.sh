#!/usr/bin/env bash
# Build the derivative dev image build-vpp-overlay-dev:latest.
#
# Idempotent: if the image already exists locally and the Dockerfile checksum
# matches the last successful build, this is a no-op. Use `--force` to rebuild.
set -euo pipefail

DEV_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$DEV_DIR/.." && pwd)"
DOCKERFILE="$DEV_DIR/Dockerfile.overlay-dev"
IMAGE_TAG="build-vpp-overlay-dev:latest"
CACHE_FILE="$DEV_DIR/.last-build-sha"
BINAPI_VERSION="v0.10.0"
BINAPI_BIN="$DEV_DIR/.binapi-generator.linux-amd64"

force=0
if [ "${1:-}" = "--force" ]; then
  force=1
fi

if [ ! -f "$DOCKERFILE" ]; then
  echo "ERROR: $DOCKERFILE not found" >&2
  exit 1
fi

# Cross-compile binapi-generator on the host for linux/amd64.
# We bake the resulting static binary into the image because Go's runtime
# crashes under qemu-user during `go install` on macOS Docker Desktop (the
# same constraint that forces run-tests.sh to cross-compile its test binary).
if [ ! -x "$BINAPI_BIN" ] || [ $force -eq 1 ]; then
  if ! command -v go >/dev/null; then
    echo "ERROR: host 'go' toolchain required to cross-compile binapi-generator" >&2
    exit 1
  fi
  echo "[build-image] cross-compiling binapi-generator@$BINAPI_VERSION (linux/amd64) on host"
  tmpdir=$(mktemp -d)
  trap 'chmod -R u+w "$tmpdir" 2>/dev/null; rm -rf "$tmpdir" 2>/dev/null' EXIT
  (
    cd "$tmpdir"
    cat > go.mod <<EOF
module bootstrap

go 1.20
EOF
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
      GOPATH="$tmpdir/gopath" GOMODCACHE="$tmpdir/gopath/pkg/mod" \
      go install "go.fd.io/govpp/cmd/binapi-generator@${BINAPI_VERSION}"
  )
  # When cross-compiling, the binary lands in $GOPATH/bin/<goos>_<goarch>/.
  src="$tmpdir/gopath/bin/linux_amd64/binapi-generator"
  [ -x "$src" ] || src="$tmpdir/gopath/bin/binapi-generator"
  mv "$src" "$BINAPI_BIN"
  chmod +x "$BINAPI_BIN"
fi

current_sha=$(shasum -a 256 "$DOCKERFILE" "$BINAPI_BIN" | shasum -a 256 | awk '{print $1}')
existing_id=$(docker images --format '{{.ID}}' "$IMAGE_TAG" | head -1 || true)

if [ $force -eq 0 ] \
   && [ -n "$existing_id" ] \
   && [ -f "$CACHE_FILE" ] \
   && [ "$(cat "$CACHE_FILE")" = "${current_sha} ${existing_id}" ]; then
  size=$(docker images --format '{{.Size}}' "$IMAGE_TAG" | head -1)
  echo "[build-image] up-to-date: $IMAGE_TAG ($existing_id, $size) — skipping"
  exit 0
fi

echo "[build-image] building $IMAGE_TAG from $DOCKERFILE"
t0=$(date +%s)
docker build -t "$IMAGE_TAG" -f "$DOCKERFILE" "$REPO_ROOT"
t1=$(date +%s)

new_id=$(docker images --format '{{.ID}}' "$IMAGE_TAG" | head -1)
size=$(docker images --format '{{.Size}}' "$IMAGE_TAG" | head -1)
printf '%s %s\n' "$current_sha" "$new_id" > "$CACHE_FILE"

echo "[build-image] OK: $IMAGE_TAG id=$new_id size=$size build_time=$((t1 - t0))s"
