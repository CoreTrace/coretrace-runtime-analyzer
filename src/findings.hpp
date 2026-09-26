// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP
#define CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP

#include "runtime_analyzer.hpp"

#include <string_view>
#include <vector>

namespace coretrace::runtime_analyzer
{
    // The memory errors the CoreTrace runtime reported in `output`, without ANSI escapes.
    [[nodiscard]] std::vector<Finding> ParseFindings(std::string_view output);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP
