# SPDX-License-Identifier: Apache-2.0
# A project consuming the library the way ctrace does: FetchContent on a release tag, the
# coretrace::runtime-analyzer_lib target, Run() on a program. The consumer test configures it
# with FETCHCONTENT_SOURCE_DIR_RUNTIME_ANALYZER pointing at the checkout under test, so the
# tag is not cloned and the working tree is what gets consumed.
cmake_minimum_required(VERSION 3.21)
project(runtime_analyzer_consumer LANGUAGES C CXX)

include(FetchContent)
FetchContent_Declare(
  runtime_analyzer
  GIT_REPOSITORY https://github.com/CoreTrace/coretrace-runtime-analyzer.git
  GIT_TAG        v0.1.0
  EXCLUDE_FROM_ALL
)
FetchContent_MakeAvailable(runtime_analyzer)

add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE coretrace::runtime-analyzer_lib)
