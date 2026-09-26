
# 3.21 for install(RUNTIME_DEPENDENCY_SET).
cmake_minimum_required(VERSION 3.21)

# ============================================================================
#  CoreTrace Runtime Analyzer
# ============================================================================

# ------------------------------
# PROJECT CONFIG
# ------------------------------
set(TOOL_NAME "runtime-analyzer" CACHE STRING "Tool/project name" FORCE)
set(TOOL_NAMESPACE "coretrace" CACHE STRING "CMake namespace for ALIAS targets")

# Library sources (add/remove files here)
set(TOOL_SOURCES
    src/findings.cpp
    src/process.cpp
    src/runtime_analyzer.cpp
    src/sarif.cpp
    src/shipped_toolchain.cpp
)

# CLI
option(BUILD_CLI "Build the CLI executable" ON)
set(TOOL_CLI_SOURCE "main.cpp" CACHE STRING "CLI entry source")

# Library kind
option(BUILD_SHARED_LIB "Build shared library variant" OFF)

# LLVM settings
set(LLVM_MIN_REQUIRED_VERSION "19" CACHE STRING "Minimum required LLVM version")
# If ON, link to monolithic LLVM target when available; otherwise link components.
set(LLVM_LINK_LLVM_DYLIB ON CACHE BOOL "Prefer linking against monolithic LLVM target")

# LLVM components to link when LLVM_LINK_LLVM_DYLIB is OFF or target LLVM is unavailable
set(LLVM_COMPONENTS
    core
    irreader
    support
)

# CoreTrace compiler dependency
option(CORETRACE_FETCH_COMPILERLIB "Fetch coretrace-compiler via FetchContent if needed" ON)
set(CORETRACE_COMPILER_GIT_REPOSITORY "https://github.com/CoreTrace/coretrace-compiler.git" CACHE STRING "coretrace-compiler repository")
# Pinned to a release tag so that builds are reproducible. v0.9.0 is the first release that
# returns code-generation errors from compile() instead of ending the host process
# (CoreTrace/coretrace-compiler#91), places the stack push after its allocas (#90) and keeps
# source paths in runtime sites (#92).
set(CORETRACE_COMPILER_GIT_TAG "v0.9.0" CACHE STRING "coretrace-compiler git tag")

# ------------------------------
# END PROJECT CONFIG
# ------------------------------

project(${TOOL_NAME} VERSION 0.1.0 LANGUAGES C CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(CheckLLVMVersion)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")
check_llvm_version(${LLVM_MIN_REQUIRED_VERSION})

# The version the CLI prints and a release tag must agree with.
set(TOOL_GENERATED_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/include")
configure_file(cmake/runtime_analyzer_version.hpp.in
               "${TOOL_GENERATED_INCLUDE_DIR}/runtime_analyzer_version.hpp" @ONLY)

include(FetchContent)

# ----------------------------------------------------------------------------
# Dependency if needed: coretrace-compiler (provides cc::compilerlib_static)
# ----------------------------------------------------------------------------
if(CORETRACE_FETCH_COMPILERLIB AND NOT TARGET cc::compilerlib_static)
    FetchContent_Declare(
      cc
      GIT_REPOSITORY ${CORETRACE_COMPILER_GIT_REPOSITORY}
      GIT_TAG        ${CORETRACE_COMPILER_GIT_TAG}
    )
    FetchContent_MakeAvailable(cc)
endif()

if(NOT TARGET cc::compilerlib_static)
    message(FATAL_ERROR "Target cc::compilerlib_static not found. Either enable CORETRACE_FETCH_COMPILERLIB or provide coretrace-compiler in your superbuild.")
endif()

# ----------------------------------------------------------------------------
# Helper: define a CoreTrace tool (library + optional CLI)
# ----------------------------------------------------------------------------
function(coretrace_add_tool)
    set(options)
    set(oneValueArgs NAME NAMESPACE CLI_SOURCE)
    set(multiValueArgs SOURCES LLVM_COMPONENTS)
    cmake_parse_arguments(CTOOL "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT CTOOL_NAME)
        message(FATAL_ERROR "coretrace_add_tool(): NAME is required")
    endif()

    if(NOT CTOOL_NAMESPACE)
        set(CTOOL_NAMESPACE "coretrace")
    endif()

    if(NOT CTOOL_SOURCES)
        message(FATAL_ERROR "coretrace_add_tool(): SOURCES is required")
    endif()

    if(BUILD_SHARED_LIB)
        set(_lib_type SHARED)
    else()
        set(_lib_type STATIC)
    endif()

    set(_lib_target "${CTOOL_NAME}_lib")

    add_library(${_lib_target} ${_lib_type}
        ${CTOOL_SOURCES}
    )

    # Public headers live in include/
    target_include_directories(${_lib_target}
        PUBLIC
            $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
            $<BUILD_INTERFACE:${TOOL_GENERATED_INCLUDE_DIR}>
            $<INSTALL_INTERFACE:include>
            ${LLVM_INCLUDE_DIRS}
    )

    # LLVM_DEFINITIONS may contain -D flags; keep behavior consistent with LLVM examples.
    if(LLVM_DEFINITIONS)
        separate_arguments(_llvm_defs NATIVE_COMMAND "${LLVM_DEFINITIONS}")
        target_compile_options(${_lib_target} PUBLIC ${_llvm_defs})
    endif()

    # Core dependency for compilation / .ll translation
    target_link_libraries(${_lib_target}
        PUBLIC
            cc::compilerlib_static
    )

    # LLVM linkage strategy
    if(LLVM_LINK_LLVM_DYLIB AND TARGET LLVM)
        target_link_libraries(${_lib_target} PUBLIC LLVM)
    else()
        # Map components to actual libraries
        if(CTOOL_LLVM_COMPONENTS)
            set(_llvm_components ${CTOOL_LLVM_COMPONENTS})
        else()
            set(_llvm_components ${LLVM_COMPONENTS})
        endif()
        llvm_map_components_to_libnames(_llvm_libs ${_llvm_components})
        target_link_libraries(${_lib_target} PUBLIC ${_llvm_libs})
    endif()

    # ALIAS for FetchContent consumers
    add_library(${CTOOL_NAMESPACE}::${_lib_target} ALIAS ${_lib_target})

    # Optional CLI
    if(BUILD_CLI)
        if(NOT CTOOL_CLI_SOURCE)
            message(FATAL_ERROR "coretrace_add_tool(): CLI_SOURCE is required when BUILD_CLI=ON")
        endif()

        add_executable(${CTOOL_NAME}
            ${CTOOL_CLI_SOURCE}
        )
        target_link_libraries(${CTOOL_NAME} PRIVATE ${_lib_target})
    endif()
endfunction()

# ----------------------------------------------------------------------------
# Instantiate the tool from USER CONFIG
# ----------------------------------------------------------------------------
coretrace_add_tool(
    NAME          ${TOOL_NAME}
    NAMESPACE     ${TOOL_NAMESPACE}
    SOURCES       ${TOOL_SOURCES}
    CLI_SOURCE    ${TOOL_CLI_SOURCE}
    LLVM_COMPONENTS ${LLVM_COMPONENTS}
)

# =========
#  INSTALL
# =========
# coretrace-compiler's own rules install bin/cc, lib/libct_instrument_runtime.a and
# lib/libcoretrace_logger.a beside these; the installed CLI links instrumented programs against
# the archives found in ../lib relative to itself, so the prefix can be moved.
install(TARGETS ${TOOL_NAME}_lib
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib
)
if(BUILD_CLI)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    # The archive is self-contained: the LLVM libraries the CLI links (libLLVM, libclang-cpp)
    # are copied into lib/, found through the rpath. libstdc++ and libgcc_s are shipped too,
    # as the build compiler may be newer than the target's and they are backward compatible.
    # glibc stays the system's: the archive runs on any glibc at least as old as the build
    # machine's.
    set_target_properties(${TOOL_NAME} PROPERTIES INSTALL_RPATH "$ORIGIN/../lib")
    install(TARGETS ${TOOL_NAME}
      RUNTIME_DEPENDENCY_SET ${TOOL_NAME}_deps
      RUNTIME DESTINATION bin
    )
    install(RUNTIME_DEPENDENCY_SET ${TOOL_NAME}_deps
      PRE_EXCLUDE_REGEXES
        "^libc\\.so"
        "^libm\\.so"
        "^libdl\\.so"
        "^librt\\.so"
        "^libpthread\\.so"
        "^ld-linux"
      DIRECTORIES ${LLVM_LIBRARY_DIRS}
      LIBRARY DESTINATION lib
    )
  else()
    install(TARGETS ${TOOL_NAME} RUNTIME DESTINATION bin)
  endif()
  # Clang's headers next to the CLI, so that no clang is needed where it runs.
  include(ClangHeaders)
endif()
install(DIRECTORY include/ DESTINATION include)
install(FILES "${TOOL_GENERATED_INCLUDE_DIR}/runtime_analyzer_version.hpp" DESTINATION include)

# ============
#  FORMATTING
# ============
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  add_custom_target(format
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/format.sh"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Run clang-format on source files")

  add_custom_target(format-check
    COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/scripts/format-check.sh"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    COMMENT "Verify clang-format compliance")
endif()

# =======
#  TESTS
# =======
# Only the top-level project runs them: FetchContent consumers do not inherit the suite.
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  enable_testing()

  add_executable(findings_test unittests/findings_test.cpp)
  target_include_directories(findings_test PRIVATE src)
  target_link_libraries(findings_test PRIVATE ${TOOL_NAME}_lib)
  add_test(NAME findings_unit COMMAND findings_test)

  add_executable(process_test unittests/process_test.cpp)
  target_include_directories(process_test PRIVATE src)
  target_link_libraries(process_test PRIVATE ${TOOL_NAME}_lib)
  add_test(NAME process_unit COMMAND process_test)

  add_executable(shipped_toolchain_test unittests/shipped_toolchain_test.cpp)
  target_include_directories(shipped_toolchain_test PRIVATE src)
  target_link_libraries(shipped_toolchain_test PRIVATE ${TOOL_NAME}_lib)
  add_test(NAME shipped_toolchain_unit COMMAND shipped_toolchain_test)

  if(BUILD_CLI)
    find_package(Python3 COMPONENTS Interpreter)
    if(Python3_Interpreter_FOUND)
      add_test(NAME findings
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/test/findings/check_findings.py"
                $<TARGET_FILE:${TOOL_NAME}> "${CMAKE_CURRENT_BINARY_DIR}/findings")
      add_test(NAME timeout
        COMMAND ${Python3_EXECUTABLE} "${CMAKE_CURRENT_SOURCE_DIR}/test/timeout/check_timeout.py"
                $<TARGET_FILE:${TOOL_NAME}> "${CMAKE_CURRENT_BINARY_DIR}/timeout")
      add_test(NAME compile_failure
        COMMAND ${Python3_EXECUTABLE}
                "${CMAKE_CURRENT_SOURCE_DIR}/test/compile_failure/check_compile_failure.py"
                $<TARGET_FILE:${TOOL_NAME}> "${CMAKE_CURRENT_BINARY_DIR}/compile_failure")
    endif()

    # A program runs and its entry/exit events are collected. A shell checks the exit status
    # and the summary together: PASS_REGULAR_EXPRESSION alone would ignore the status.
    set(_hello_out "${CMAKE_CURRENT_BINARY_DIR}/hello.out")
    add_test(NAME hello_runs
      COMMAND sh -c "\"$<TARGET_FILE:${TOOL_NAME}>\" -o \"${CMAKE_CURRENT_BINARY_DIR}/hello\" -- test/examples/fixtures/hello.c > \"${_hello_out}\" && grep -q 'entry_events=[1-9]' \"${_hello_out}\" && grep -q 'exit_events=[1-9]' \"${_hello_out}\""
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

    # Every source under test/ compiles: the sweep exits 0 only when no test fails to build.
    add_test(NAME sweep_compiles
      COMMAND $<TARGET_FILE:${TOOL_NAME}> --test-dir test --no-run
              --output-dir "${CMAKE_CURRENT_BINARY_DIR}/sweep"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

    # Every binary runs to completion within the timeout. Several fixtures report findings on
    # purpose, so the exit status is 1: the pass expression makes CTest ignore it, and any
    # [TIMEOUT] or [COMPILE] record fails the test.
    add_test(NAME sweep_runs
      COMMAND $<TARGET_FILE:${TOOL_NAME}> --test-dir test --timeout 10
              --output-dir "${CMAKE_CURRENT_BINARY_DIR}/sweep-run" -- --ct-modules=alloc
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
    set_tests_properties(sweep_runs PROPERTIES
      PASS_REGULAR_EXPRESSION "runtime-analyzer: batch"
      FAIL_REGULAR_EXPRESSION "\\[TIMEOUT\\];\\[COMPILE\\]")

    # The CLI states the version a release tag must agree with.
    add_test(NAME version
      COMMAND sh -c "\"$<TARGET_FILE:${TOOL_NAME}>\" --version | grep -x '${TOOL_NAME} ${PROJECT_VERSION}'")

    # Configuration fails, rather than warns, against an LLVM below the floor.
    add_test(NAME llvm_floor
      COMMAND ${CMAKE_COMMAND} -S "${CMAKE_CURRENT_SOURCE_DIR}"
              -B "${CMAKE_CURRENT_BINARY_DIR}/llvm-floor"
              -DLLVM_DIR=${LLVM_DIR} -DClang_DIR=${Clang_DIR} -DLLVM_MIN_REQUIRED_VERSION=99)
    set_tests_properties(llvm_floor PROPERTIES
      PASS_REGULAR_EXPRESSION "needs LLVM 99 or later")

    # An installed prefix holds the CLI, the library and the headers, and its CLI builds and
    # runs an instrumented program with the runtime archives installed next to it.
    set(_prefix "${CMAKE_CURRENT_BINARY_DIR}/prefix")
    add_test(NAME install_layout
      COMMAND sh -c "rm -rf \"${_prefix}\" && ${CMAKE_COMMAND} --install \"${CMAKE_CURRENT_BINARY_DIR}\" --prefix \"${_prefix}\" > /dev/null && test -f \"${_prefix}/lib/lib${TOOL_NAME}_lib.a\" && test -f \"${_prefix}/include/runtime_analyzer.hpp\" && test -f \"${_prefix}/include/runtime_analyzer_version.hpp\" && test -f \"${_prefix}\"/lib/clang/*/include/stddef.h && \"${_prefix}/bin/${TOOL_NAME}\" --version && \"${_prefix}/bin/${TOOL_NAME}\" -o \"${_prefix}/hello\" -- test/examples/fixtures/hello.c"
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
  endif()
endif()
