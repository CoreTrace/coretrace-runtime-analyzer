// SPDX-License-Identifier: Apache-2.0
// Checks what the analyzer reads from a run: the CoreTrace event lines, their summary, and the
// verdict it draws from a result.
#include "events.hpp"

#include "expect.hpp"

#include <string>
#include <vector>

namespace
{
    using coretrace::runtime_analyzer::AnalyzerResult;
    using coretrace::runtime_analyzer::CollectEvents;
    using coretrace::runtime_analyzer::CollectionSummary;
    using coretrace::runtime_analyzer::Finding;
    using coretrace::runtime_analyzer::kExitFindings;
    using coretrace::runtime_analyzer::kExitNoFindings;
    using coretrace::runtime_analyzer::kExitNotAnalyzed;
    using coretrace::runtime_analyzer::MergeSummaries;
    using coretrace::runtime_analyzer::StripAnsi;
    using coretrace::runtime_analyzer::Verdict;
    using unittests::Expect;

    void AnsiSequencesAreStripped()
    {
        Expect(StripAnsi("\x1b[31mred\x1b[0m plain") == "red plain", "ANSI: colours removed");
        Expect(StripAnsi("no escape") == "no escape", "ANSI: untouched otherwise");
    }

    void OnlyCoreTraceLinesAreEvents()
    {
        const std::string output =
            "hello from the program\n"
            "|1| ==ct== [INFO] tracing-malloc :: site=a.c:6:19\n"
            "[ENTRY-FUNCTION] main\n"
            "[EXIT-FUNCTION] main\n"
            "\x1b[31m|1| ==ct== [ERROR] ct: heap-buffer-overflow WRITE\x1b[0m\n"
            "|1| ==ct== [WARN] ct: leak ptr=0x1 size=16\n"
            "[VTABLE-DIAG] box\n"
            "bye\n";
        std::vector<std::string> events;
        const CollectionSummary summary = CollectEvents(output, events);
        Expect(events.size() == 6 && summary.coretrace_lines == 6,
               "events: the six CoreTrace lines, not the program's own");
        Expect(events[3] == "|1| ==ct== [ERROR] ct: heap-buffer-overflow WRITE",
               "events: kept without their colours");
        Expect(summary.entry_events == 1 && summary.exit_events == 1, "summary: entry and exit");
        Expect(summary.allocation_events == 2, "summary: the malloc trace and the leak");
        Expect(summary.bounds_errors == 1 && summary.leak_reports == 1,
               "summary: bounds error and leak report");
        Expect(summary.vtable_events == 1, "summary: vtable diagnostic");
        Expect(summary.warnings == 1 && summary.errors == 1, "summary: one WARN, one ERROR");
    }

    void SummariesAdd()
    {
        CollectionSummary a{1, 2, 3, 4, 5, 6, 7, 8, 9};
        const CollectionSummary b{10, 20, 30, 40, 50, 60, 70, 80, 90};
        a = MergeSummaries(a, b);
        Expect(a.coretrace_lines == 11 && a.entry_events == 22 && a.exit_events == 33 &&
                   a.allocation_events == 44 && a.bounds_errors == 55 && a.leak_reports == 66 &&
                   a.vtable_events == 77 && a.warnings == 88 && a.errors == 99,
               "merge: every counter adds up");
    }

    void TheVerdict()
    {
        AnalyzerResult result;
        Expect(Verdict(result, true) == kExitNotAnalyzed, "verdict: not built is 2");
        result.compile_success = true;
        Expect(Verdict(result, true) == kExitNotAnalyzed, "verdict: built but not run is 2");
        Expect(Verdict(result, false) == kExitNoFindings, "verdict: compile only is 0");
        result.executed = true;
        Expect(Verdict(result, true) == kExitNoFindings, "verdict: clean run is 0");
        result.exit_code = 3;
        Expect(Verdict(result, true) == kExitNoFindings,
               "verdict: the program's own status is not a finding");
        result.timed_out = true;
        Expect(Verdict(result, true) == kExitNotAnalyzed,
               "verdict: timed out without findings is 2");
        result.findings.push_back(Finding{"memory-leak", "CWE-401"});
        Expect(Verdict(result, true) == kExitFindings, "verdict: findings are 1, even timed out");
    }
} // namespace

int main()
{
    AnsiSequencesAreStripped();
    OnlyCoreTraceLinesAreEvents();
    SummariesAdd();
    TheVerdict();
    return unittests::Finish("events_test");
}
