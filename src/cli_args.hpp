// SPDX-License-Identifier: Apache-2.0
// The CLI's arguments: their parsing, the compiler arguments derived from them and from each
// source, and where batch mode puts each binary.
#ifndef CORETRACE_RUNTIME_ANALYZER_CLI_ARGS_HPP
#define CORETRACE_RUNTIME_ANALYZER_CLI_ARGS_HPP

#include "runtime_analyzer.hpp"

#include <filesystem>
#include <string>
#include <string_view>
#include <vector>

namespace coretrace::runtime_analyzer
{
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
        std::string error; // why `ok` is false
    };

    [[nodiscard]] ParseResult ParseArgs(int argc, char** argv);

    struct OutputArgument
    {
        bool present = false;
        std::string path;
    };

    // The compiler's own -o, --output, -o=<path> or --output=<path>, if any.
    [[nodiscard]] OutputArgument FindOutputArgument(const std::vector<std::string>& args);

    // -c, -S, -E and the like: no executable comes out of the compiler.
    [[nodiscard]] bool HasCompileOnlyAction(const std::vector<std::string>& args);
    [[nodiscard]] bool HasLanguageOverride(const std::vector<std::string>& args);

    // A .c source written in C++, which clang has to be told about.
    [[nodiscard]] bool CSourceLooksLikeCxx(const std::filesystem::path& source,
                                           std::string_view text);
    [[nodiscard]] bool SourceRequiresDebugDefine(std::string_view text);
    // Appends -x c++ and -DDEBUG when the source needs them and the user gave neither.
    void AddPerSourceCompatibilityArgs(const std::filesystem::path& source,
                                       std::vector<std::string>& args);

    // The compiler arguments of a run: --instrument dropped, -o appended unless the compiler
    // has one. `output_path` receives the binary's path either way.
    [[nodiscard]] std::vector<std::string> BuildCompilerArguments(const AnalyzerOptions& options,
                                                                  std::string& output_path);

    // Letters, digits, - and _ only; "test" for an empty path.
    [[nodiscard]] std::string SanitizeArtifactName(const std::filesystem::path& path);
    // <output directory>/<sanitized source path without extension>_<stable 16-digit hash>.
    [[nodiscard]] std::filesystem::path MakeTestOutputPath(const AnalyzerOptions& options,
                                                           const std::filesystem::path& source);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_CLI_ARGS_HPP
