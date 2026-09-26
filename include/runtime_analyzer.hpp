// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_HPP
#define CORETRACE_RUNTIME_ANALYZER_HPP

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace coretrace::runtime_analyzer
{
    struct AnalyzerOptions
    {
        std::vector<std::string> compiler_args;
        std::vector<std::string> program_args;
        std::vector<std::string> environment;
        std::vector<std::string> test_directories;
        std::string output_path = "runtime-analyzer.out";
        std::string output_directory = "runtime-analyzer-artifacts";
        std::string working_directory;
        std::chrono::milliseconds timeout{60000}; // per program run; 0 disables the limit
        bool explicit_output_path = false;
        bool run_program = true;
        bool show_program_output = false;
        bool show_events = false;
        bool strict_test_exit = false;
    };

    struct CollectionSummary
    {
        std::uint64_t coretrace_lines = 0;
        std::uint64_t entry_events = 0;
        std::uint64_t exit_events = 0;
        std::uint64_t allocation_events = 0;
        std::uint64_t bounds_errors = 0;
        std::uint64_t leak_reports = 0;
        std::uint64_t vtable_events = 0;
        std::uint64_t warnings = 0;
        std::uint64_t errors = 0;
    };

    struct SourceLocation
    {
        std::string file;
        unsigned line = 0;
        unsigned column = 0; // 0 when the runtime reports none
    };

    enum class Severity
    {
        Warning,
        Error,
    };

    // One runtime report, as an editor or a SARIF consumer can use it.
    struct Finding
    {
        std::string rule; // e.g. "heap-buffer-overflow"
        std::string cwe;  // e.g. "CWE-122"
        Severity severity = Severity::Error;
        std::string message;                      // stable text: no addresses
        std::optional<SourceLocation> location;   // the faulting access
        std::optional<SourceLocation> allocation; // where the memory was allocated
    };

    struct AnalyzerResult
    {
        bool success = false;
        bool compile_success = false;
        bool executed = false;
        bool timed_out = false; // the run passed the timeout and was killed
        int exit_code = 1;      // the program's own exit status
        std::string output_path;
        std::string diagnostics;
        std::string stdout_text;
        std::string stderr_text;
        std::vector<std::string> coretrace_events;
        std::vector<Finding> findings;
        CollectionSummary summary;
    };

    struct TestFileResult
    {
        std::string source_path;
        AnalyzerResult analyzer_result;
    };

    struct BatchResult
    {
        bool success = false;
        // The analyzer's verdict: 0 without findings, 1 with findings, 2 when a program could
        // not be built or run.
        int exit_code = 2;
        std::vector<TestFileResult> tests;
        CollectionSummary summary;
        std::string diagnostics;
        std::uint64_t compile_failures = 0;
        std::uint64_t runtime_failures = 0;
        std::uint64_t timeouts = 0;
    };

    [[nodiscard]] AnalyzerResult Run(const AnalyzerOptions& options);
    [[nodiscard]] BatchResult RunBatch(const AnalyzerOptions& options);
    [[nodiscard]] int Main(int argc, char** argv);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_HPP
