// SPDX-License-Identifier: Apache-2.0
#include "cli_args.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace coretrace::runtime_analyzer
{
    namespace
    {
        constexpr std::string_view kDefaultOutputPath = "runtime-analyzer.out";

        [[nodiscard]] bool IsCompileOnlyFlag(std::string_view arg)
        {
            return arg == "-c" || arg == "-S" || arg == "-E" || arg == "-emit-llvm" ||
                   arg == "--precompile" || arg == "-fsyntax-only";
        }

        [[nodiscard]] bool Contains(std::string_view haystack, std::string_view needle)
        {
            return haystack.find(needle) != std::string_view::npos;
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

        [[nodiscard]] bool IsValidEnvironmentAssignment(std::string_view assignment)
        {
            const std::size_t eq = assignment.find('=');
            return eq != std::string_view::npos && eq != 0;
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
    } // namespace

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

    [[nodiscard]] std::vector<std::string> BuildCompilerArguments(const AnalyzerOptions& options,
                                                                  std::string& output_path)
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
               (SanitizeArtifactName(artifact_name) + "_" + HexDigest(StablePathHash(hash_input)));
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
            result.error = "unknown analyzer option: " + arg + " (compiler arguments go after --)";
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
} // namespace coretrace::runtime_analyzer
