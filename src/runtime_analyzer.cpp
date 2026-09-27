// SPDX-License-Identifier: Apache-2.0
#include "runtime_analyzer.hpp"
#include "runtime_analyzer_version.hpp"

#include "cli_args.hpp"
#include "compilerlib/compiler.h"
#include "events.hpp"
#include "findings.hpp"
#include "process.hpp"
#include "sarif.hpp"
#include "shipped_toolchain.hpp"

#include <llvm/Support/FileSystem.h>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>

namespace coretrace::runtime_analyzer
{
    namespace
    {
        [[nodiscard]] bool IsSourceFile(const std::filesystem::path& path)
        {
            const std::string ext = path.extension().string();
            return ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx";
        }

        [[nodiscard]] std::string AbsolutePathForExecution(std::string_view output_path)
        {
            std::error_code error;
            std::filesystem::path path(output_path);
            std::filesystem::path absolute = std::filesystem::absolute(path, error);
            if (error)
            {
                return std::string(output_path);
            }
            return absolute.string();
        }

        [[nodiscard]] std::vector<std::filesystem::path>
        DiscoverSourceFiles(const std::vector<std::string>& directories, std::string& diagnostics)
        {
            std::vector<std::filesystem::path> sources;
            for (const std::string& directory : directories)
            {
                std::error_code error;
                const std::filesystem::path root(directory);
                if (!std::filesystem::exists(root, error))
                {
                    diagnostics += "test directory does not exist: " + directory + "\n";
                    continue;
                }
                if (!std::filesystem::is_directory(root, error))
                {
                    diagnostics += "test path is not a directory: " + directory + "\n";
                    continue;
                }

                std::filesystem::recursive_directory_iterator it(
                    root, std::filesystem::directory_options::skip_permission_denied, error);
                const std::filesystem::recursive_directory_iterator end;
                while (!error && it != end)
                {
                    const std::filesystem::directory_entry& entry = *it;
                    if (entry.is_regular_file(error) && IsSourceFile(entry.path()))
                    {
                        sources.push_back(entry.path());
                    }
                    it.increment(error);
                }
                if (error)
                {
                    diagnostics += "failed while scanning test directory " + directory + ": " +
                                   error.message() + "\n";
                }
            }

            std::ranges::sort(sources);
            sources.erase(std::ranges::unique(sources).begin(), sources.end());
            return sources;
        }

        void PrintHelp(std::ostream& out)
        {
            out << "Usage: runtime-analyzer [options] -- <compiler args>\n\n"
                << "Builds an instrumented binary with coretrace-compiler library mode, runs it, "
                   "and collects basic runtime events.\n\n"
                << "Options:\n"
                << "  -o, --output <path>       Instrumented binary path when compiler args do "
                   "not contain -o\n"
                << "  --run-arg <value>         Argument passed to the instrumented binary\n"
                << "  --env NAME=VALUE          Environment variable passed to the "
                   "instrumented binary\n"
                << "  --cwd <path>              Working directory used when running the binary\n"
                << "  --timeout <seconds>       Kill the binary after this long (default 60, 0 "
                   "disables)\n"
                << "  --test-dir <path>         Run every C/C++ source file under a test "
                   "directory\n"
                << "  --output-dir <path>       Artifact directory used by --test-dir\n"
                << "  --strict-test-exit        Make batch mode fail when any test binary exits "
                   "non-zero\n"
                << "  --no-run                  Compile only, without executing the binary\n"
                << "  --show-output             Print captured stdout/stderr after the summary\n"
                << "  --show-events             Print collected CoreTrace event lines\n"
                << "  --format <text|sarif>     Print a text summary (default) or a SARIF log "
                   "of the findings\n"
                << "  -h, --help                Show this help\n"
                << "  --version                 Print the version and exit\n\n"
                << "Exit status: 0 without findings, 1 with findings, 2 when the program could "
                   "not be built or run.\n\n"
                << "Example:\n"
                << "  runtime-analyzer -o ./app -- --ct-modules=trace,alloc,bounds main.c\n";
        }

        void PrintLocation(const SourceLocation& location)
        {
            std::cout << location.file << ':' << location.line;
            if (location.column != 0)
            {
                std::cout << ':' << location.column;
            }
            std::cout << ": ";
        }

        // One compiler-style line per finding, with the allocation site as a note below it.
        void PrintFindings(const std::vector<Finding>& findings, std::string_view indent)
        {
            for (const Finding& finding : findings)
            {
                std::cout << indent;
                if (finding.location)
                {
                    PrintLocation(*finding.location);
                }
                std::cout << (finding.severity == Severity::Error ? "error: " : "warning: ")
                          << finding.message << " [" << finding.rule << ", " << finding.cwe
                          << "]\n";
                if (finding.allocation)
                {
                    std::cout << indent << "  ";
                    PrintLocation(*finding.allocation);
                    std::cout << "note: allocated here\n";
                }
            }
        }

        void PrintResult(const AnalyzerResult& result, const AnalyzerOptions& options)
        {
            std::cout << "runtime-analyzer: binary=" << result.output_path << '\n';
            std::cout << "runtime-analyzer: exit_code=" << result.exit_code << '\n';
            std::cout << "runtime-analyzer: timed_out=" << (result.timed_out ? 1 : 0) << '\n';
            std::cout << "runtime-analyzer: findings=" << result.findings.size() << '\n';
            PrintFindings(result.findings, "  ");
            std::cout << "runtime-analyzer: collection\n";
            std::cout << "  coretrace_lines=" << result.summary.coretrace_lines << '\n';
            std::cout << "  entry_events=" << result.summary.entry_events << '\n';
            std::cout << "  exit_events=" << result.summary.exit_events << '\n';
            std::cout << "  allocation_events=" << result.summary.allocation_events << '\n';
            std::cout << "  bounds_errors=" << result.summary.bounds_errors << '\n';
            std::cout << "  leak_reports=" << result.summary.leak_reports << '\n';
            std::cout << "  vtable_events=" << result.summary.vtable_events << '\n';
            std::cout << "  warnings=" << result.summary.warnings << '\n';
            std::cout << "  errors=" << result.summary.errors << '\n';

            if (options.show_events && !result.coretrace_events.empty())
            {
                std::cout << "\nruntime-analyzer: events\n";
                for (const std::string& event : result.coretrace_events)
                {
                    std::cout << event << '\n';
                }
            }

            if (options.show_program_output)
            {
                std::cout << "\nruntime-analyzer: stdout\n";
                std::cout << result.stdout_text;
                if (!result.stdout_text.empty() && result.stdout_text.back() != '\n')
                {
                    std::cout << '\n';
                }

                std::cout << "\nruntime-analyzer: stderr\n";
                std::cout << result.stderr_text;
                if (!result.stderr_text.empty() && result.stderr_text.back() != '\n')
                {
                    std::cout << '\n';
                }
            }
        }

        [[nodiscard]] std::vector<Finding> AllFindings(const BatchResult& result)
        {
            std::vector<Finding> findings;
            for (const TestFileResult& test : result.tests)
            {
                findings.insert(findings.end(), test.analyzer_result.findings.begin(),
                                test.analyzer_result.findings.end());
            }
            return findings;
        }

        void PrintBatchResult(const BatchResult& result, const AnalyzerOptions& options)
        {
            std::cout << "runtime-analyzer: batch\n";
            std::cout << "  tests=" << result.tests.size() << '\n';
            std::cout << "  compile_failures=" << result.compile_failures << '\n';
            std::cout << "  runtime_failures=" << result.runtime_failures << '\n';
            std::cout << "  timeouts=" << result.timeouts << '\n';
            std::cout << "  coretrace_lines=" << result.summary.coretrace_lines << '\n';
            std::cout << "  entry_events=" << result.summary.entry_events << '\n';
            std::cout << "  exit_events=" << result.summary.exit_events << '\n';
            std::cout << "  allocation_events=" << result.summary.allocation_events << '\n';
            std::cout << "  bounds_errors=" << result.summary.bounds_errors << '\n';
            std::cout << "  leak_reports=" << result.summary.leak_reports << '\n';
            std::cout << "  vtable_events=" << result.summary.vtable_events << '\n';
            std::cout << "  warnings=" << result.summary.warnings << '\n';
            std::cout << "  errors=" << result.summary.errors << '\n';

            for (const TestFileResult& test : result.tests)
            {
                const AnalyzerResult& analyzer = test.analyzer_result;
                const char* status = "PASS";
                if (!analyzer.compile_success)
                {
                    status = "COMPILE";
                }
                else if (analyzer.timed_out)
                {
                    status = "TIMEOUT";
                }
                else if (!analyzer.success)
                {
                    status = "RUNTIME";
                }

                std::cout << "runtime-analyzer: [" << status << "] " << test.source_path
                          << " exit_code=" << analyzer.exit_code
                          << " coretrace_lines=" << analyzer.summary.coretrace_lines
                          << " binary=" << analyzer.output_path << '\n';
                PrintFindings(analyzer.findings, "  ");

                if (options.show_events && !analyzer.coretrace_events.empty())
                {
                    for (const std::string& event : analyzer.coretrace_events)
                    {
                        std::cout << "  " << event << '\n';
                    }
                }
            }
        }
    } // namespace

    [[nodiscard]] AnalyzerResult Run(const AnalyzerOptions& options)
    {
        AnalyzerResult result;
        if (HasCompileOnlyAction(options.compiler_args) && options.run_program)
        {
            result.diagnostics =
                "runtime-analyzer requires a linked executable; remove compile-only flags or pass "
                "--no-run";
            return result;
        }

        std::string output_path;
        std::vector<std::string> compiler_args = BuildCompilerArguments(options, output_path);
        if (options.explicit_output_path)
        {
            const OutputArgument forwarded_output = FindOutputArgument(options.compiler_args);
            if (forwarded_output.present)
            {
                result.diagnostics = "output path specified twice: use analyzer -o/--output or "
                                     "compiler -o, not both";
                return result;
            }
        }

        compilerlib::CompileResult compile_result =
            compilerlib::compile(compiler_args, compilerlib::OutputMode::ToFile, true);
        result.diagnostics = compile_result.diagnostics;
        result.output_path = output_path;
        if (!compile_result.success)
        {
            return result;
        }
        result.compile_success = true;

        if (!options.run_program)
        {
            result.success = true;
            result.exit_code = 0;
            return result;
        }

        ProcessResult process =
            RunProcess({AbsolutePathForExecution(output_path), options.program_args,
                        options.environment, options.working_directory, options.timeout});
        result.stdout_text = std::move(process.stdout_text);
        result.stderr_text = std::move(process.stderr_text);
        result.exit_code = process.exit_code;
        result.executed = process.error.empty();
        result.timed_out = process.timed_out;
        if (process.timed_out)
        {
            const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(options.timeout);
            result.diagnostics +=
                "program timed out after " + std::to_string(seconds.count()) + " s\n";
        }
        if (!process.error.empty())
        {
            result.diagnostics += process.error;
            if (!result.diagnostics.empty() && result.diagnostics.back() != '\n')
            {
                result.diagnostics.push_back('\n');
            }
            return result;
        }

        std::vector<std::string> stdout_events;
        std::vector<std::string> stderr_events;
        CollectionSummary stdout_summary = CollectEvents(result.stdout_text, stdout_events);
        CollectionSummary stderr_summary = CollectEvents(result.stderr_text, stderr_events);
        result.summary = MergeSummaries(stdout_summary, stderr_summary);
        result.coretrace_events.reserve(stdout_events.size() + stderr_events.size());
        result.coretrace_events.insert(result.coretrace_events.end(),
                                       std::make_move_iterator(stdout_events.begin()),
                                       std::make_move_iterator(stdout_events.end()));
        result.coretrace_events.insert(result.coretrace_events.end(),
                                       std::make_move_iterator(stderr_events.begin()),
                                       std::make_move_iterator(stderr_events.end()));

        for (const std::string* text : {&result.stdout_text, &result.stderr_text})
        {
            std::vector<Finding> findings = ParseFindings(StripAnsi(*text));
            result.findings.insert(result.findings.end(), std::make_move_iterator(findings.begin()),
                                   std::make_move_iterator(findings.end()));
        }

        result.success = result.exit_code == 0;
        return result;
    }

    [[nodiscard]] BatchResult RunBatch(const AnalyzerOptions& options)
    {
        BatchResult batch;
        if (HasCompileOnlyAction(options.compiler_args) && options.run_program)
        {
            batch.diagnostics = "runtime-analyzer batch mode requires linked executables; remove "
                                "compile-only flags "
                                "or pass --no-run";
            return batch;
        }

        std::error_code error;
        std::filesystem::create_directories(options.output_directory, error);
        if (error)
        {
            batch.diagnostics = "failed to create output directory " + options.output_directory +
                                ": " + error.message();
            return batch;
        }

        std::string discovery_diagnostics;
        const std::vector<std::filesystem::path> sources =
            DiscoverSourceFiles(options.test_directories, discovery_diagnostics);
        batch.diagnostics += discovery_diagnostics;
        if (sources.empty())
        {
            batch.diagnostics += "no C/C++ test sources found\n";
            return batch;
        }

        int verdict = kExitNoFindings;
        for (const std::filesystem::path& source : sources)
        {
            AnalyzerOptions test_options = options;
            test_options.test_directories.clear();
            test_options.output_path = MakeTestOutputPath(options, source).string();
            test_options.explicit_output_path = true;
            test_options.compiler_args = options.compiler_args;
            AddPerSourceCompatibilityArgs(source, test_options.compiler_args);
            test_options.compiler_args.push_back(source.string());
            std::filesystem::remove(test_options.output_path, error);
            error.clear();

            AnalyzerResult analyzer = Run(test_options);
            if (!analyzer.diagnostics.empty())
            {
                batch.diagnostics += source.string() + ":\n" + analyzer.diagnostics;
                if (!batch.diagnostics.empty() && batch.diagnostics.back() != '\n')
                {
                    batch.diagnostics.push_back('\n');
                }
            }

            if (analyzer.output_path.empty())
            {
                analyzer.output_path = test_options.output_path;
            }

            if (!analyzer.compile_success)
            {
                ++batch.compile_failures;
            }
            else if (analyzer.timed_out)
            {
                ++batch.timeouts;
            }
            else if (analyzer.exit_code != 0)
            {
                ++batch.runtime_failures;
            }
            verdict = std::max(verdict, Verdict(analyzer, options.run_program));
            batch.summary = MergeSummaries(batch.summary, analyzer.summary);
            batch.tests.push_back(TestFileResult{source.string(), std::move(analyzer)});
        }

        const bool runtime_ok = options.strict_test_exit ? batch.runtime_failures == 0 : true;
        batch.success = batch.compile_failures == 0 && runtime_ok;
        batch.exit_code = runtime_ok ? verdict : std::max(verdict, kExitFindings);
        return batch;
    }

    [[nodiscard]] int Main(int argc, char** argv)
    {
        ParseResult parsed = ParseArgs(argc, argv);
        if (parsed.help)
        {
            PrintHelp(std::cout);
            return 0;
        }
        if (parsed.version)
        {
            std::cout << "runtime-analyzer " << kVersion << '\n';
            return 0;
        }

        // An installed CLI carries Clang's headers and the C++ runtime next to itself; a
        // build-tree one does not, and coretrace-compiler then falls back on the toolchain it
        // was configured with.
        const std::filesystem::path executable =
            llvm::sys::fs::getMainExecutable(argv[0], reinterpret_cast<void*>(&Main));
        (void)UseShippedClangHeaders(executable);
        if (!HasCompileOnlyAction(parsed.options.compiler_args))
        {
            const std::vector<std::string> link = ShippedLinkArguments(executable);
            parsed.options.compiler_args.insert(parsed.options.compiler_args.end(), link.begin(),
                                                link.end());
        }
        if (!parsed.ok)
        {
            std::cerr << "runtime-analyzer: " << parsed.error << '\n';
            PrintHelp(std::cerr);
            return kExitNotAnalyzed;
        }

        if (!parsed.options.test_directories.empty())
        {
            BatchResult result = RunBatch(parsed.options);
            if (!result.diagnostics.empty())
            {
                std::cerr << result.diagnostics;
                if (result.diagnostics.back() != '\n')
                {
                    std::cerr << '\n';
                }
            }
            if (parsed.format == OutputFormat::Sarif)
            {
                WriteSarif(std::cout, AllFindings(result));
            }
            else
            {
                PrintBatchResult(result, parsed.options);
            }
            return result.exit_code;
        }

        AnalyzerResult result = Run(parsed.options);
        if (!result.diagnostics.empty())
        {
            std::cerr << result.diagnostics;
            if (result.diagnostics.back() != '\n')
            {
                std::cerr << '\n';
            }
        }

        if (result.output_path.empty())
        {
            result.output_path = parsed.options.output_path;
        }
        if (parsed.format == OutputFormat::Sarif)
        {
            WriteSarif(std::cout, result.findings);
        }
        else
        {
            PrintResult(result, parsed.options);
        }
        return Verdict(result, parsed.options.run_program);
    }
} // namespace coretrace::runtime_analyzer
