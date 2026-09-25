// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP
#define CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP

#include "runtime_analyzer.hpp"

#include <ostream>
#include <string>
#include <string_view>
#include <vector>

namespace coretrace::runtime_analyzer
{
    // The memory errors the CoreTrace runtime reported in `output`, without ANSI escapes.
    // The runtime names a file by its base name: a name matching exactly one of `sources`
    // takes that source's path.
    [[nodiscard]] std::vector<Finding> ParseFindings(std::string_view output,
                                                     const std::vector<std::string>& sources);

    // A SARIF 2.1.0 log with one run holding `findings`.
    void WriteSarif(std::ostream& out, const std::vector<Finding>& findings);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP
