// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_SHIPPED_TOOLCHAIN_HPP
#define CORETRACE_RUNTIME_ANALYZER_SHIPPED_TOOLCHAIN_HPP

#include <filesystem>

namespace coretrace::runtime_analyzer
{
    // Points coretrace-compiler at the Clang headers installed next to the CLI, at
    // <exe dir>/../lib/clang/<version>/include, by setting CT_CLANG to the CLI itself: the
    // resource directory is derived from that path. Returns whether it did. A CT_CLANG set by
    // the user keeps priority, and an empty executable path ships nothing.
    [[nodiscard]] bool UseShippedClangHeaders(const std::filesystem::path& executable);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_SHIPPED_TOOLCHAIN_HPP
