# SPDX-License-Identifier: Apache-2.0
#
# Clang's own headers (stddef.h, stdarg.h, the intrinsics...) are needed to compile any C or
# C++ source, and they ship with clang, not with the system. The analyzer compiles programs in
# process through coretrace-compiler, which finds them relative to a clang path: installing them
# at <prefix>/lib/clang/<version>/include, next to bin/runtime-analyzer, lets the CLI point
# coretrace-compiler at itself (UseShippedClangHeaders), so that no clang has to be installed
# where the analyzer runs.
#
# They are taken from the clang coretrace-compiler was configured with (CLANG_EXECUTABLE), the
# one whose headers match the linked Clang libraries.
if(NOT CLANG_EXECUTABLE)
  message(FATAL_ERROR "CLANG_EXECUTABLE is not set: cannot locate Clang's headers to install")
endif()
execute_process(
  COMMAND ${CLANG_EXECUTABLE} -print-resource-dir
  OUTPUT_VARIABLE _clang_resource_dir
  OUTPUT_STRIP_TRAILING_WHITESPACE
  RESULT_VARIABLE _clang_resource_status)
if(NOT _clang_resource_status EQUAL 0 OR NOT EXISTS "${_clang_resource_dir}/include/stddef.h")
  message(FATAL_ERROR "No Clang headers at '${_clang_resource_dir}/include' "
                      "(${CLANG_EXECUTABLE} -print-resource-dir)")
endif()
get_filename_component(_clang_version "${_clang_resource_dir}" NAME)

install(DIRECTORY "${_clang_resource_dir}/include" DESTINATION lib/clang/${_clang_version})
