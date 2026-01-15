
cmake_minimum_required(VERSION 3.16)

# ============================================================================
#  CoreTrace Tool Template — Generic CMakeLists
#
#  Goal: a consumer should only edit the section "USER CONFIG" below.
# ============================================================================

# ------------------------------
# USER CONFIG (edit this block)
# ------------------------------
set(TOOL_NAME "your_tool_name" CACHE STRING "Tool/project name")
set(TOOL_NAMESPACE "coretrace" CACHE STRING "CMake namespace for ALIAS targets")

# Library sources (add/remove files here)
set(TOOL_SOURCES
    src/your_tool_name.cpp
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
set(CORETRACE_COMPILER_GIT_TAG "main" CACHE STRING "coretrace-compiler git tag")

# ------------------------------
# END USER CONFIG
# ------------------------------

project(${TOOL_NAME} LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
include(CheckLLVMVersion OPTIONAL)

if(COMMAND check_llvm_version)
    check_llvm_version(${LLVM_MIN_REQUIRED_VERSION})
else()
    message(WARNING "check_llvm_version() not available, skipping LLVM version check")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(LLVM REQUIRED CONFIG)
message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

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
