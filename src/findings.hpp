// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP
#define CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP

#include "runtime_analyzer.hpp"

#include <optional>
#include <string_view>
#include <vector>

namespace coretrace::runtime_analyzer
{
    // The memory errors the CoreTrace runtime reported in `output`, without ANSI escapes.
    [[nodiscard]] std::vector<Finding> ParseFindings(std::string_view output);

    // What a rule checks, for a SARIF consumer to explain the rule's findings.
    struct RuleDescription
    {
        std::string_view title;
        std::string_view description;
    };

    // The description of `rule`; nothing for a rule this analyzer does not report.
    [[nodiscard]] std::optional<RuleDescription> DescribeRule(std::string_view rule);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_FINDINGS_HPP
