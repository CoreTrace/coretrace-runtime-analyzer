// SPDX-License-Identifier: Apache-2.0
// What the analyzer reads from a run: the CoreTrace event lines, their summary, and the
// verdict it draws from a result.
#ifndef CORETRACE_RUNTIME_ANALYZER_EVENTS_HPP
#define CORETRACE_RUNTIME_ANALYZER_EVENTS_HPP

#include "runtime_analyzer.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace coretrace::runtime_analyzer
{
    // The analyzer's verdict; the program's own status stays in AnalyzerResult::exit_code.
    constexpr int kExitNoFindings = 0;
    constexpr int kExitFindings = 1;
    constexpr int kExitNotAnalyzed = 2;

    [[nodiscard]] std::string StripAnsi(std::string_view input);

    // Appends the CoreTrace lines of `text`, without their colours, to `events`, and counts
    // them.
    [[nodiscard]] CollectionSummary CollectEvents(std::string_view text,
                                                  std::vector<std::string>& events);
    [[nodiscard]] CollectionSummary MergeSummaries(CollectionSummary lhs,
                                                   const CollectionSummary& rhs);

    [[nodiscard]] int Verdict(const AnalyzerResult& result, bool run_program);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_EVENTS_HPP
