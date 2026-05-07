#!/usr/bin/env bash
# Phase 1 verification: build + control-plane CLI tests + Go integration tests.
#
# Note: VPP runs in an x86_64 container under Docker Desktop's qemu
# emulation. Recent Go runtimes (1.21+) crash under qemu-user when GC kicks
# in. We work around this by cross-compiling the Go test binary on the host
# and copying the static binary into the container — the container only
# needs to *run* it, not invoke the Go toolchain.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PLUGIN_SRC="$REPO_ROOT/src/plugins/overlay"
DEV_DIR="$REPO_ROOT/dev"
GO_DIR="$DEV_DIR/go-overlay"
IMAGE="build-vpp-overlay-dev:latest"

GO_BIN=/tmp/overlay-test.amd64
echo "=== [host] Cross-compiling Go test binary (if stale) ==="
need_rebuild=1
if [ -x "$GO_BIN" ]; then
  stale=$(find "$GO_DIR" -name '*.go' -not -path '*/vendor/*' -newer "$GO_BIN" -print -quit)
  if [ -z "$stale" ]; then
    need_rebuild=0
  fi
fi
if [ $need_rebuild -eq 1 ]; then
  (cd "$GO_DIR" && \
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go test -c -o "$GO_BIN" ./)
  echo "go test binary rebuilt: $(ls -lh "$GO_BIN" | awk '{print $5}')"
else
  echo "go test binary up to date: $(ls -lh "$GO_BIN" | awk '{print $5}')"
fi

HOST_SCRATCH=$(mktemp -d)
trap "rm -rf $HOST_SCRATCH" EXIT

echo "=== [container] Build plugin + run tests ==="
docker run --rm \
  --cap-add SYS_PTRACE \
  -v "$PLUGIN_SRC":/plugin/overlay:ro \
  -v "$DEV_DIR":/dev-wrapper:ro \
  -v "$HOST_SCRATCH":/out \
  -v "$GO_BIN":/usr/local/bin/overlay-test:ro \
  "$IMAGE" bash -c '
    set -euo pipefail

    # Build/test deps are baked into build-vpp-overlay-dev:latest.
    # Run dev/build-image.sh to (re)build the image.

    echo "--- Configuring + building plugin ---"
    mkdir -p /build && cd /build
    cmake /dev-wrapper \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/usr \
      -DVPP_LIBRARY_DIR=/usr/lib/x86_64-linux-gnu \
      2>&1 | tail -3
    mkdir -p CMakeFiles/vpp-api/vapi
    make -j"$(nproc)" 2>&1 | grep -E "(Linking|error:)" || true
    make install 2>&1 | grep "Installing.*overlay" || true
    ls -lh /usr/lib/x86_64-linux-gnu/vpp_plugins/overlay_plugin.so

    # Export api.json + full api dir to the host for the binapi-generator
    # reproducibility check that runs after this container exits. The
    # plugin build sometimes drops overlay.api.json under /build instead of
    # the install path, so locate it dynamically.
    OVERLAY_API_JSON=$(find /usr/share/vpp/api /build -name overlay.api.json -print 2>/dev/null | head -1)
    if [ -z "$OVERLAY_API_JSON" ]; then
      echo "ERROR: overlay.api.json not found"
      exit 1
    fi
    cp "$OVERLAY_API_JSON" /out/overlay.api.json
    cp -r /usr/share/vpp/api /out/api
    mkdir -p /out/api/plugins
    cp /out/overlay.api.json /out/api/plugins/overlay.api.json

    SHA=$(sha256sum "$OVERLAY_API_JSON" | awk "{print \$1}")
    echo "overlay.api.json sha256: $SHA"

    echo ""
    echo "--- Starting VPP with CLI + binary API socket ---"
    mkdir -p /run/vpp
    cat > /tmp/vpp.conf <<EOF
unix { nodaemon log /tmp/vpp.log cli-listen /tmp/vpp.sock }
api-segment { gid root }
socksvr { socket-name /run/vpp/api.sock }
plugins {
  plugin dpdk_plugin.so   { disable }
  plugin overlay_plugin.so { enable  }
}
EOF
    vpp -c /tmp/vpp.conf >/tmp/vpp.stdout 2>&1 &
    VPP_PID=$!
    trap "kill $VPP_PID 2>/dev/null || true" EXIT

    for i in $(seq 1 60); do
      [ -S /tmp/vpp.sock ] && [ -S /run/vpp/api.sock ] && break
      sleep 0.5
    done
    if [ ! -S /tmp/vpp.sock ] || [ ! -S /run/vpp/api.sock ]; then
      echo "ERROR: VPP did not start"
      cat /tmp/vpp.log || true
      cat /tmp/vpp.stdout || true
      exit 1
    fi

    vppctl -s /tmp/vpp.sock show plugins | grep "overlay_plugin.so" >/dev/null \
      || { echo "overlay plugin not loaded"; exit 1; }

    echo ""
    echo "=== Running pytest (CLI control plane) ==="
    # binary is mounted ro from the host; it is already executable.
    cd /dev-wrapper/tests
    PYTEST_RC=0
    python3 -m pytest -v --color=no || PYTEST_RC=$?

    echo ""
    echo "=== Running go test (binary API integration) ==="
    GO_RC=0
    VPP_API_SOCK=/run/vpp/api.sock VPP_CLI_SOCK=/tmp/vpp.sock \
      /usr/local/bin/overlay-test -test.v || GO_RC=$?

    if [ $PYTEST_RC -ne 0 ] || [ $GO_RC -ne 0 ]; then
      echo "FAIL: pytest=$PYTEST_RC go=$GO_RC"
      exit 1
    fi

    echo ""
    echo "=== ACCEPTANCE: PASS ==="
  '

echo "=== [host] Verifying generated Go bindings reproduce from current api ==="
if command -v binapi-generator >/dev/null; then
  GEN_OUT=$HOST_SCRATCH/gen
  mkdir -p "$GEN_OUT"
  binapi-generator \
    --input="$HOST_SCRATCH/api" \
    --output-dir="$GEN_OUT" \
    --import-prefix=github.com/yafimk/vpp-overlay/dev/go-overlay \
    overlay memclnt 2>&1 | tail -3
  for d in interface_types ip_types memclnt overlay; do
    if ! diff -ruN "$GO_DIR/$d" "$GEN_OUT/$d" >/dev/null; then
      echo "ERROR: regenerated bindings differ from committed copy in $d"
      diff -ruN "$GO_DIR/$d" "$GEN_OUT/$d" | head -50
      exit 1
    fi
  done
  echo "go bindings: clean (no diff)"
else
  echo "binapi-generator not installed on host; skipping reproducibility check"
  echo "  (install via: go install go.fd.io/govpp/cmd/binapi-generator@v0.10.0)"
fi
