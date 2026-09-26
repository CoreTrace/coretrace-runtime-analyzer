# SPDX-License-Identifier: Apache-2.0
# check_llvm_version(<minimum major>): fails configuration when the LLVM found by
# find_package(LLVM) is older than the floor, instead of failing later at compile or link
# time with an unhelpful error.
function(check_llvm_version minimum)
  if(NOT DEFINED LLVM_PACKAGE_VERSION)
    message(FATAL_ERROR "check_llvm_version() must be called after find_package(LLVM)")
  endif()
  if(LLVM_PACKAGE_VERSION VERSION_LESS minimum)
    message(FATAL_ERROR
      "${PROJECT_NAME} needs LLVM ${minimum} or later; ${LLVM_DIR} is LLVM ${LLVM_PACKAGE_VERSION}")
  endif()
  message(STATUS "LLVM ${LLVM_PACKAGE_VERSION} satisfies the LLVM ${minimum} floor")
endfunction()
