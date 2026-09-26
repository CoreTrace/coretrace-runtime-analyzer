// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_SHIPPED_TOOLCHAIN_HPP
#define CORETRACE_RUNTIME_ANALYZER_SHIPPED_TOOLCHAIN_HPP

#include <filesystem>
#include <string>
#include <vector>

namespace coretrace::runtime_analyzer
{
    // Points coretrace-compiler at the Clang headers installed next to the CLI, at
    // <exe dir>/../lib/clang/<version>/include, by setting CT_CLANG to the CLI itself: the
    // resource directory is derived from that path. Returns whether it did. A CT_CLANG set by
    // the user keeps priority, and an empty executable path ships nothing.
    [[nodiscard]] bool UseShippedClangHeaders(const std::filesystem::path& executable);

    // Compiler arguments that link an instrumented program against the C++ runtime shipped
    // next to the CLI, at <exe dir>/../lib: "-L<lib>" and "-Wl,-rpath,<lib>" when that
    // directory holds libstdc++.so, nothing otherwise. The runtime archives are built with a
    // compiler newer than the target's may be, so its libstdc++ is shipped and linked instead
    // of the system's.
    [[nodiscard]] std::vector<std::string>
    ShippedLinkArguments(const std::filesystem::path& executable);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_SHIPPED_TOOLCHAIN_HPP
