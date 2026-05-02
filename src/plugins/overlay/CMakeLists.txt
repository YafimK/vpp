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
