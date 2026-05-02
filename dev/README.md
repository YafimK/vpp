# dev/ — local inner-loop for the overlay plugin

Local development scaffolding for `src/plugins/overlay/`. Not part of the
upstream VPP PR — these files exist only to drive a fast build/test loop on a
developer workstation.

## Build the dev image

```sh
./dev/build-image.sh
```

Produces `build-vpp-overlay-dev:latest`, derived from `build-vpp-test:latest`
with `build-essential cmake python3-ply python3-pytest python3-docutils
golang-go git` and `binapi-generator@v0.10.0` pre-installed. The script is
idempotent — re-running it after the Dockerfile is unchanged is a no-op. Pass
`--force` to rebuild unconditionally.

## Run the test loop

```sh
./dev/run-tests.sh
```

Builds the plugin, boots VPP, and runs pytest + Go integration tests.

Prerequisites:

- Docker Desktop (or compatible) running.
- Base image `build-vpp-test:latest` available locally (Ubuntu 22.04 + VPP
  24.02 + vpp-dev). Build or pull this out-of-band; the dev image derives
  from it.
- A working host Go toolchain — `run-tests.sh` cross-compiles the Go test
  binary on the host and mounts it into the container as a workaround for a
  qemu-user / Go GC interaction.

## What's where

| Path             | Purpose                                                    |
| ---------------- | ---------------------------------------------------------- |
| `overlay/`       | (in `src/plugins/overlay/`) — the plugin source under test |
| `dev/`           | This directory: dev-only Dockerfile, scripts, CMake glue   |
| `dev/tests/`     | pytest suite for the CLI / control plane                   |
| `dev/go-overlay/`| Go bindings + integration test using the binary API socket |
