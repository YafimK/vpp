# Copyright (c) 2026 Check Point Software Technologies, Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include_directories(${CMAKE_SOURCE_DIR})

# For generated API headers (overlay.api_enum.h, overlay.api_types.h)
include_directories(${CMAKE_BINARY_DIR})

# Bake build identity at compile time so `show overlay version` can surface
# which build is loaded without sha256sum'ing the .so.
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

add_vpp_plugin(overlay
  SOURCES
    overlay.c
    decap.c
    node.c

  # Encap is the hot path; compile node.c for SSE2/AVX2/AVX-512 variants.
  # decap.c is buffer-strip + metadata reset, not compute-bound.
  MULTIARCH_SOURCES
    node.c

  API_FILES
    overlay.api

  INSTALL_HEADERS
    overlay.h
)
