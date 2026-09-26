// SPDX-License-Identifier: Apache-2.0
// Checks the library API a consumer such as ctrace links: Run and RunBatch on real programs,
// compiled with coretrace-compiler, executed, and reported through the public structures.
#include "runtime_analyzer.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

namespace
{
    using coretrace::runtime_analyzer::AnalyzerOptions;
    using coretrace::runtime_analyzer::AnalyzerResult;
    using coretrace::runtime_analyzer::BatchResult;
    using coretrace::runtime_analyzer::Finding;
    using coretrace::runtime_analyzer::Run;
    using coretrace::runtime_analyzer::RunBatch;
    using coretrace::runtime_analyzer::Severity;

    constexpr std::string_view kHang = "#include <unistd.h>\nint main(void)\n{\n    for (;;)\n"
                                       "        pause();\n}\n";
    constexpr std::string_view kNormal = "int main(void)\n{\n    return 0;\n}\n";

    int failures = 0;
    std::filesystem::path fixtures; // the repository's test/ directory
    std::filesystem::path work;     // scratch directory, outside test/ (the sweeps run it)

    void Expect(bool condition, std::string_view what)
    {
        std::cout << (condition ? "[PASS] " : "[FAIL] ") << what << '\n';
        if (!condition)
        {
            ++failures;
        }
    }

    [[nodiscard]] bool Contains(std::string_view text, std::string_view needle)
    {
        return text.find(needle) != std::string_view::npos;
    }

    [[nodiscard]] std::filesystem::path Write(std::string_view name, std::string_view text)
    {
        const std::filesystem::path path = work / name;
        std::filesystem::create_directories(path.parent_path());
        std::ofstream(path) << text;
        return path;
    }

    [[nodiscard]] AnalyzerOptions Options(const std::filesystem::path& source,
                                          std::string_view output)
    {
        AnalyzerOptions options;
        options.compiler_args = {"--ct-modules=alloc,bounds", source.string()};
        options.output_path = (work / output).string();
        options.explicit_output_path = true;
        return options;
    }

    void RunReportsTheHeapOverflow()
    {
        const std::filesystem::path source = fixtures / "findings" / "heap_overflow_write.c";
        const AnalyzerResult result = Run(Options(source, "heap_overflow_write"));
        Expect(result.compile_success, "overflow: compiled");
        Expect(result.executed && !result.timed_out, "overflow: executed to completion");
        Expect(result.findings.size() == 1, "overflow: one finding");
        if (result.findings.size() != 1)
        {
            return;
        }
        const Finding& finding = result.findings.front();
        Expect(finding.rule == "heap-buffer-overflow" && finding.cwe == "CWE-122",
               "overflow: rule and CWE");
        Expect(finding.severity == Severity::Error, "overflow: an error");
        Expect(!finding.message.empty(), "overflow: has a message");
        // The runtime names the source as coretrace-compiler recorded it, which may be a
        // relative path: only its tail is checked.
        Expect(finding.location &&
                   finding.location->file.ends_with("findings/heap_overflow_write.c") &&
                   finding.location->line == 7 && finding.location->column > 0,
               "overflow: located at the faulting write in the source");
        Expect(finding.allocation && finding.allocation->file == finding.location->file &&
                   finding.allocation->line == 6,
               "overflow: the allocation site, in the same source");
    }

    void CompileOnlyDoesNotRun()
    {
        AnalyzerOptions options =
            Options(fixtures / "findings" / "heap_overflow_write.c", "compile_only");
        options.run_program = false;
        const AnalyzerResult result = Run(options);
        Expect(result.compile_success && result.success && result.exit_code == 0,
               "compile only: a success without a run");
        Expect(!result.executed && result.findings.empty(), "compile only: nothing executed");
        Expect(std::filesystem::exists(result.output_path),
               "compile only: the binary is at output_path");
    }

    void TimeoutKillsAHangingProgram()
    {
        AnalyzerOptions options = Options(Write("hang.c", kHang), "hang");
        options.timeout = std::chrono::seconds(1);
        const auto start = std::chrono::steady_clock::now();
        const AnalyzerResult result = Run(options);
        const auto elapsed = std::chrono::steady_clock::now() - start;
        Expect(result.compile_success, "hang: compiled");
        Expect(result.timed_out && !result.success, "hang: timed out, not a success");
        Expect(Contains(result.diagnostics, "timed out after 1 s"), "hang: diagnostics say so");
        Expect(elapsed < std::chrono::seconds(10), "hang: returned within a few seconds");
    }

    void RunBatchReportsEachSource()
    {
        const std::filesystem::path directory = work / "batch";
        (void)Write("batch/hang.c", kHang);
        (void)Write("batch/normal.c", kNormal);
        std::filesystem::copy_file(fixtures / "findings" / "heap_overflow_write.c",
                                   directory / "heap_overflow_write.c",
                                   std::filesystem::copy_options::overwrite_existing);

        AnalyzerOptions options;
        options.compiler_args = {"--ct-modules=alloc,bounds"};
        options.test_directories = {directory.string()};
        options.output_directory = (work / "batch-artifacts").string();
        options.timeout = std::chrono::seconds(1);
        const BatchResult batch = RunBatch(options);

        Expect(batch.tests.size() == 3, "batch: three sources analyzed");
        if (batch.tests.size() != 3)
        {
            return;
        }
        Expect(std::filesystem::path(batch.tests[0].source_path).filename() == "hang.c" &&
                   std::filesystem::path(batch.tests[1].source_path).filename() ==
                       "heap_overflow_write.c" &&
                   std::filesystem::path(batch.tests[2].source_path).filename() == "normal.c",
               "batch: sources in path order");
        Expect(batch.tests[0].analyzer_result.timed_out, "batch: hang.c timed out");
        Expect(batch.tests[1].analyzer_result.findings.size() == 1 &&
                   batch.tests[1].analyzer_result.findings.front().rule == "heap-buffer-overflow",
               "batch: heap_overflow_write.c has its finding");
        Expect(batch.tests[2].analyzer_result.success &&
                   batch.tests[2].analyzer_result.findings.empty(),
               "batch: normal.c ran clean");
        Expect(batch.compile_failures == 0 && batch.timeouts == 1, "batch: counters");
        Expect(batch.success, "batch: a success, as no source failed to build");
        Expect(batch.exit_code == 2, "batch: verdict 2, a program was not analyzed to completion");
    }

    void RefusesCompileOnlyFlagsWithARun()
    {
        AnalyzerOptions options =
            Options(fixtures / "findings" / "heap_overflow_write.c", "object");
        options.compiler_args.insert(options.compiler_args.begin(), "-c");
        const AnalyzerResult result = Run(options);
        Expect(!result.compile_success && !result.executed, "-c with a run: refused");
        Expect(Contains(result.diagnostics, "--no-run"), "-c with a run: names --no-run");
    }

    void EmptyBatchIsNotAnalyzed()
    {
        std::filesystem::create_directories(work / "empty");
        AnalyzerOptions options;
        options.test_directories = {(work / "empty").string()};
        options.output_directory = (work / "empty-artifacts").string();
        const BatchResult batch = RunBatch(options);
        Expect(!batch.success && batch.exit_code == 2 && batch.tests.empty(),
               "empty directory: not analyzed");
        Expect(Contains(batch.diagnostics, "no C/C++ test sources found"),
               "empty directory: diagnostics say so");
    }
} // namespace

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: api_test <test directory> <work directory>\n";
        return 2;
    }
    fixtures = std::filesystem::absolute(argv[1]);
    work = std::filesystem::absolute(argv[2]);
    std::filesystem::remove_all(work);
    std::filesystem::create_directories(work);

    RunReportsTheHeapOverflow();
    CompileOnlyDoesNotRun();
    TimeoutKillsAHangingProgram();
    RunBatchReportsEachSource();
    RefusesCompileOnlyFlagsWithARun();
    EmptyBatchIsNotAnalyzed();
    if (failures != 0)
    {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "api_test: all checks passed\n";
    return 0;
}
