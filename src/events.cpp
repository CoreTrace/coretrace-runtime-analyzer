// SPDX-License-Identifier: Apache-2.0
#include "events.hpp"

#include <sstream>
#include <utility>

namespace coretrace::runtime_analyzer
{
    namespace
    {
        [[nodiscard]] bool Contains(std::string_view haystack, std::string_view needle)
        {
            return haystack.find(needle) != std::string_view::npos;
        }

        [[nodiscard]] bool IsCoreTraceLine(std::string_view line)
        {
            return Contains(line, "==ct==") || Contains(line, "ct:") ||
                   Contains(line, "[ENTRY-FUNCTION]") || Contains(line, "[EXIT-FUNCTION]") ||
                   Contains(line, "[VTABLE-DIAG]") || Contains(line, "tracing-") ||
                   Contains(line, "auto-free") || Contains(line, "heap-buffer-overflow") ||
                   Contains(line, "heap-use-after-free");
        }

        void UpdateSummary(std::string_view line, CollectionSummary& summary)
        {
            if (Contains(line, "[ENTRY-FUNCTION]") || Contains(line, "ct: enter "))
            {
                ++summary.entry_events;
            }
            if (Contains(line, "[EXIT-FUNCTION]"))
            {
                ++summary.exit_events;
            }
            if (Contains(line, "tracing-") || Contains(line, "auto-free") ||
                Contains(line, "leaks detected") || Contains(line, "ct: leak "))
            {
                ++summary.allocation_events;
            }
            if (Contains(line, "heap-buffer-overflow") || Contains(line, "heap-use-after-free"))
            {
                ++summary.bounds_errors;
            }
            if (Contains(line, "leaks detected") || Contains(line, "ct: leak "))
            {
                ++summary.leak_reports;
            }
            if (Contains(line, "[VTABLE-DIAG]"))
            {
                ++summary.vtable_events;
            }
            if (Contains(line, "[WARN]") || Contains(line, " WARN "))
            {
                ++summary.warnings;
            }
            if (Contains(line, "[ERROR]") || Contains(line, " ERROR "))
            {
                ++summary.errors;
            }
        }
    } // namespace

    [[nodiscard]] std::string StripAnsi(std::string_view input)
    {
        std::string output;
        output.reserve(input.size());
        for (std::size_t i = 0; i < input.size(); ++i)
        {
            if (input[i] == '\x1b' && i + 1 < input.size() && input[i + 1] == '[')
            {
                i += 2;
                while (i < input.size() && !((input[i] >= 'A' && input[i] <= 'Z') ||
                                             (input[i] >= 'a' && input[i] <= 'z')))
                {
                    ++i;
                }
                continue;
            }
            output.push_back(input[i]);
        }
        return output;
    }

    [[nodiscard]] CollectionSummary CollectEvents(std::string_view text,
                                                  std::vector<std::string>& events)
    {
        CollectionSummary summary;
        std::istringstream stream(std::string(StripAnsi(text)));
        std::string line;
        while (std::getline(stream, line))
        {
            if (!IsCoreTraceLine(line))
            {
                continue;
            }

            ++summary.coretrace_lines;
            UpdateSummary(line, summary);
            events.push_back(std::move(line));
        }
        return summary;
    }

    [[nodiscard]] CollectionSummary MergeSummaries(CollectionSummary lhs,
                                                   const CollectionSummary& rhs)
    {
        lhs.coretrace_lines += rhs.coretrace_lines;
        lhs.entry_events += rhs.entry_events;
        lhs.exit_events += rhs.exit_events;
        lhs.allocation_events += rhs.allocation_events;
        lhs.bounds_errors += rhs.bounds_errors;
        lhs.leak_reports += rhs.leak_reports;
        lhs.vtable_events += rhs.vtable_events;
        lhs.warnings += rhs.warnings;
        lhs.errors += rhs.errors;
        return lhs;
    }

    [[nodiscard]] int Verdict(const AnalyzerResult& result, bool run_program)
    {
        if (!result.compile_success || (run_program && !result.executed))
        {
            return kExitNotAnalyzed;
        }
        if (!result.findings.empty())
        {
            return kExitFindings;
        }
        // A program killed at the timeout was not analyzed to completion.
        return result.timed_out ? kExitNotAnalyzed : kExitNoFindings;
    }
} // namespace coretrace::runtime_analyzer
