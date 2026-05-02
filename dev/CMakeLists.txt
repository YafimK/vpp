# Dev-only external-build wrapper.
# Lets the container build src/plugins/overlay/ against the prebuilt
# vpp-dev package instead of the full VPP source tree.
# Not part of the upstream contribution.

cmake_minimum_required(VERSION 3.10)
project(overlay-plugin-external)
find_package(VPP REQUIRED)

# Plugin code uses <overlay/overlay.h> — that's an in-tree-style include.
# /plugin acts as the equivalent of vpp/src/plugins/, so headers resolve.
include_directories(/plugin)

# Use binary-subdir name "overlay" so generated <overlay/overlay.api_enum.h>
# resolves via include_directories(${CMAKE_BINARY_DIR}) in the plugin.
add_subdirectory(/plugin/overlay overlay)
