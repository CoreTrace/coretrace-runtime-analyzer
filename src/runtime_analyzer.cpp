// SPDX-License-Identifier: Apache-2.0
#include "runtime_analyzer.hpp"
#include "runtime_analyzer_version.hpp"

#include "compilerlib/compiler.h"
#include "findings.hpp"
#include "process.hpp"
#include "sarif.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

namespace coretrace::runtime_analyzer
{
    namespace
    {
        constexpr std::string_view kDefaultOutputPath = "runtime-analyzer.out";

        // The analyzer's verdict; the program's own status stays in AnalyzerResult::exit_code.
        constexpr int kExitNoFindings = 0;
        constexpr int kExitFindings = 1;
        constexpr int kExitNotAnalyzed = 2;

        enum class OutputFormat
        {
            Text,
            Sarif,
        };

        struct ParseResult
        {
            bool ok = true;
            bool help = false;
            bool version = false;
            AnalyzerOptions options;
            OutputFormat format = OutputFormat::Text;
            std::string error;
        };

        struct OutputArgument
        {
            bool present = false;
            std::string path;
        };

        [[nodiscard]] bool IsCompileOnlyFlag(std::string_view arg)
        {
            return arg == "-c" || arg == "-S" || arg == "-E" || arg == "-emit-llvm" ||
                   arg == "--precompile" || arg == "-fsyntax-only";
        }

        [[nodiscard]] bool IsSourceFile(const std::filesystem::path& path)
        {
            const std::string ext = path.extension().string();
            return ext == ".c" || ext == ".cc" || ext == ".cpp" || ext == ".cxx";
        }

        [[nodiscard]] bool Contains(std::string_view haystack, std::string_view needle)
        {
            return haystack.find(needle) != std::string_view::npos;
        }

        [[nodiscard]] bool HasCompileOnlyAction(const std::vector<std::string>& args)
        {
            return std::ranges::any_of(args, IsCompileOnlyFlag);
        }

        [[nodiscard]] bool HasLanguageOverride(const std::vector<std::string>& args)
        {
            for (std::size_t i = 0; i < args.size(); ++i)
            {
                if (args[i] == "-x" && i + 1 < args.size())
                {
                    return true;
                }
                if (args[i].rfind("-x=", 0) == 0 || args[i].rfind("-x", 0) == 0)
                {
                    return true;
                }
            }
            return false;
        }

        [[nodiscard]] std::string ReadSmallTextFile(const std::filesystem::path& path)
        {
            std::ifstream input(path);
            if (!input)
            {
                return {};
            }

            std::ostringstream output;
            output << input.rdbuf();
            return output.str();
        }

        [[nodiscard]] bool CSourceLooksLikeCxx(const std::filesystem::path& source,
                                               std::string_view text)
        {
            if (source.extension() != ".c")
            {
                return false;
            }
            return Contains(text, "#include <string>") || Contains(text, "#include <iostream>") ||
                   Contains(text, "std::") || Contains(text, "static_cast<") ||
                   Contains(text, "reinterpret_cast<") || Contains(text, "class ") ||
                   Contains(text, "namespace ") || Contains(text, "template <") ||
                   Contains(text, "virtual ");
        }

        [[nodiscard]] bool SourceRequiresDebugDefine(std::string_view text)
        {
            return Contains(text, "#ifndef DEBUG") || Contains(text, "#if !defined(DEBUG)");
        }

        void AddPerSourceCompatibilityArgs(const std::filesystem::path& source,
                                           std::vector<std::string>& args)
        {
            const std::string text = ReadSmallTextFile(source);
            if (!HasLanguageOverride(args) && CSourceLooksLikeCxx(source, text))
            {
                args.emplace_back("-x");
                args.emplace_back("c++");
            }
            if (SourceRequiresDebugDefine(text) &&
                std::ranges::none_of(args, [](const std::string& arg)
                                     { return arg == "-DDEBUG" || arg == "-DDEBUG=1"; }))
            {
                args.emplace_back("-DDEBUG");
            }
        }

        [[nodiscard]] OutputArgument FindOutputArgument(const std::vector<std::string>& args)
        {
            OutputArgument result;
            for (std::size_t i = 0; i < args.size(); ++i)
            {
                const std::string& arg = args[i];
                if (arg == "-o" || arg == "--output")
                {
                    result.present = true;
                    if (i + 1 < args.size())
                    {
                        result.path = args[i + 1];
                    }
                    return result;
                }
                if (arg.rfind("-o=", 0) == 0)
                {
                    result.present = true;
                    result.path = arg.substr(3);
                    return result;
                }
                if (arg.rfind("--output=", 0) == 0)
                {
                    result.present = true;
                    result.path = arg.substr(9);
                    return result;
                }
            }
            return result;
        }

        [[nodiscard]] std::vector<std::string>
        BuildCompilerArguments(const AnalyzerOptions& options, std::string& output_path)
        {
            std::vector<std::string> args;
            args.reserve(options.compiler_args.size() + 2);
            for (const std::string& arg : options.compiler_args)
            {
                if (arg == "--instrument")
                {
                    continue;
                }
                args.push_back(arg);
            }

            const OutputArgument output = FindOutputArgument(args);
            if (output.present)
            {
                output_path = output.path;
                return args;
            }

            output_path =
                options.output_path.empty() ? std::string(kDefaultOutputPath) : options.output_path;
            args.emplace_back("-o");
            args.push_back(output_path);
            return args;
        }

        [[nodiscard]] bool IsValidEnvironmentAssignment(std::string_view assignment)
        {
            const std::size_t eq = assignment.find('=');
            return eq != std::string_view::npos && eq != 0;
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

        [[nodiscard]] std::string SanitizeArtifactName(const std::filesystem::path& path)
        {
            std::string name = path.generic_string();
            for (char& ch : name)
            {
                const bool keep = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                                  (ch >= '0' && ch <= '9') || ch == '-' || ch == '_';
                if (!keep)
                {
                    ch = '_';
                }
            }
            if (name.empty())
            {
                return "test";
            }
            return name;
        }

        [[nodiscard]] std::uint64_t StablePathHash(std::string_view text)
        {
            constexpr std::uint64_t kFnvOffsetBasis = 14695981039346656037ULL;
            constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

            std::uint64_t hash = kFnvOffsetBasis;
            for (const char ch : text)
            {
                hash ^= static_cast<unsigned char>(ch);
                hash *= kFnvPrime;
            }
            return hash;
        }

        [[nodiscard]] std::string HexDigest(std::uint64_t value)
        {
            std::ostringstream output;
            output << std::hex << std::nouppercase << std::setfill('0') << std::setw(16) << value;
            return output.str();
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

        [[nodiscard]] std::filesystem::path MakeTestOutputPath(const AnalyzerOptions& options,
                                                               const std::filesystem::path& source)
        {
            std::error_code error;
            std::filesystem::path relative = std::filesystem::relative(source, error);
            if (error)
            {
                relative = source.filename();
            }

            const std::string hash_input = relative.generic_string();
            std::filesystem::path artifact_name = relative;
            artifact_name.replace_extension();
            return std::filesystem::path(options.output_directory) /
                   (SanitizeArtifactName(artifact_name) + "_" +
                    HexDigest(StablePathHash(hash_input)));
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

        [[nodiscard]] ParseResult ParseArgs(int argc, char** argv)
        {
            ParseResult result;
            bool compiler_args = false;

            for (int i = 1; i < argc; ++i)
            {
                std::string arg = argv[i];
                if (compiler_args)
                {
                    result.options.compiler_args.push_back(std::move(arg));
                    continue;
                }

                if (arg == "--")
                {
                    compiler_args = true;
                    continue;
                }
                if (arg == "-h" || arg == "--help")
                {
                    result.help = true;
                    return result;
                }
                if (arg == "--version")
                {
                    result.version = true;
                    return result;
                }
                if (arg == "-o" || arg == "--output")
                {
                    if (i + 1 >= argc)
                    {
                        result.ok = false;
                        result.error = arg + " requires a value";
                        return result;
                    }
                    result.options.output_path = argv[++i];
                    result.options.explicit_output_path = true;
                    continue;
                }
                if (arg.rfind("--output=", 0) == 0)
                {
                    result.options.output_path = arg.substr(9);
                    result.options.explicit_output_path = true;
                    continue;
                }
                if (arg == "--run-arg")
                {
                    if (i + 1 >= argc)
                    {
                        result.ok = false;
                        result.error = "--run-arg requires a value";
                        return result;
                    }
                    result.options.program_args.emplace_back(argv[++i]);
                    continue;
                }
                if (arg == "--env")
                {
                    if (i + 1 >= argc)
                    {
                        result.ok = false;
                        result.error = "--env requires NAME=VALUE";
                        return result;
                    }
                    std::string assignment = argv[++i];
                    if (!IsValidEnvironmentAssignment(assignment))
                    {
                        result.ok = false;
                        result.error = "--env requires NAME=VALUE";
                        return result;
                    }
                    result.options.environment.push_back(std::move(assignment));
                    continue;
                }
                if (arg == "--cwd")
                {
                    if (i + 1 >= argc)
                    {
                        result.ok = false;
                        result.error = "--cwd requires a path";
                        return result;
                    }
                    result.options.working_directory = argv[++i];
                    continue;
                }
                if (arg == "--timeout")
                {
                    if (i + 1 >= argc)
                    {
                        result.ok = false;
                        result.error = "--timeout requires a number of seconds";
                        return result;
                    }
                    const std::string value = argv[++i];
                    std::size_t consumed = 0;
                    long long seconds = -1;
                    try
                    {
                        seconds = std::stoll(value, &consumed);
                    }
                    catch (const std::exception&)
                    {
                    }
                    if (consumed != value.size() || seconds < 0)
                    {
                        result.ok = false;
                        result.error = "--timeout requires a non-negative number of seconds";
                        return result;
                    }
                    result.options.timeout = std::chrono::seconds(seconds);
                    continue;
                }
                if (arg == "--test-dir")
                {
                    if (i + 1 >= argc)
                    {
                        result.ok = false;
                        result.error = "--test-dir requires a path";
                        return result;
                    }
                    result.options.test_directories.emplace_back(argv[++i]);
                    continue;
                }
                if (arg == "--output-dir")
                {
                    if (i + 1 >= argc)
                    {
                        result.ok = false;
                        result.error = "--output-dir requires a path";
                        return result;
                    }
                    result.options.output_directory = argv[++i];
                    continue;
                }
                if (arg == "--strict-test-exit")
                {
                    result.options.strict_test_exit = true;
                    continue;
                }
                if (arg == "--no-run")
                {
                    result.options.run_program = false;
                    continue;
                }
                if (arg == "--show-output")
                {
                    result.options.show_program_output = true;
                    continue;
                }
                if (arg == "--show-events")
                {
                    result.options.show_events = true;
                    continue;
                }
                if (arg == "--format" || arg.rfind("--format=", 0) == 0)
                {
                    std::string value;
                    if (arg != "--format")
                    {
                        value = arg.substr(9);
                    }
                    else if (i + 1 < argc)
                    {
                        value = argv[++i];
                    }
                    if (value == "text" || value == "sarif")
                    {
                        result.format = value == "sarif" ? OutputFormat::Sarif : OutputFormat::Text;
                        continue;
                    }
                    result.ok = false;
                    result.error = "--format requires text or sarif";
                    return result;
                }

                result.ok = false;
                result.error =
                    "unknown analyzer option: " + arg + " (compiler arguments go after --)";
                return result;
            }

            if ((!compiler_args || result.options.compiler_args.empty()) &&
                result.options.test_directories.empty())
            {
                result.ok = false;
                result.error = "missing compiler arguments; use -- <compiler args>";
            }

            return result;
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
