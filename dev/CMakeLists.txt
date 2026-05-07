# Dev-only external-build wrapper.
# Lets the container build src/plugins/overlay/ against the prebuilt
# vpp-dev package instead of the full VPP source tree.
# Not part of the upstream contribution.

cmake_minimum_required(VERSION 3.10)
project(overlay-plugin-external)
find_package(VPP REQUIRED)

# Bake build identity at compile time. In the test container the source is
# bind-mounted without .git, so values fall back to "unknown" — that's
# expected. When built outside the container (e.g. dev/build-plugin.sh from a
# real working tree), git provides real values.
execute_process(
  COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} rev-parse HEAD
  OUTPUT_VARIABLE OVERLAY_BUILD_SHA
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
  RESULT_VARIABLE _git_sha_rc)
if(NOT _git_sha_rc EQUAL 0 OR OVERLAY_BUILD_SHA STREQUAL "")
  set(OVERLAY_BUILD_SHA "unknown")
endif()

execute_process(
  COMMAND git -C ${CMAKE_CURRENT_SOURCE_DIR} rev-parse --abbrev-ref HEAD
  OUTPUT_VARIABLE OVERLAY_BUILD_BRANCH
  OUTPUT_STRIP_TRAILING_WHITESPACE
  ERROR_QUIET
  RESULT_VARIABLE _git_branch_rc)
if(NOT _git_branch_rc EQUAL 0 OR OVERLAY_BUILD_BRANCH STREQUAL "")
  set(OVERLAY_BUILD_BRANCH "unknown")
endif()

string(TIMESTAMP OVERLAY_BUILD_DATE "%Y-%m-%dT%H:%M:%SZ" UTC)

add_definitions(
  -DOVERLAY_BUILD_SHA="${OVERLAY_BUILD_SHA}"
  -DOVERLAY_BUILD_BRANCH="${OVERLAY_BUILD_BRANCH}"
  -DOVERLAY_BUILD_DATE="${OVERLAY_BUILD_DATE}")

# Plugin code uses <overlay/overlay.h> — that's an in-tree-style include.
# /plugin acts as the equivalent of vpp/src/plugins/, so headers resolve.
include_directories(/plugin)

# Use binary-subdir name "overlay" so generated <overlay/overlay.api_enum.h>
# resolves via include_directories(${CMAKE_BINARY_DIR}) in the plugin.
add_subdirectory(/plugin/overlay overlay)
