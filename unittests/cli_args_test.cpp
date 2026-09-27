// SPDX-License-Identifier: Apache-2.0
// Checks the CLI's argument parsing and the per-source compiler arguments it derives.
#include "cli_args.hpp"

#include "expect.hpp"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace
{
    using coretrace::runtime_analyzer::AddPerSourceCompatibilityArgs;
    using coretrace::runtime_analyzer::AnalyzerOptions;
    using coretrace::runtime_analyzer::BuildCompilerArguments;
    using coretrace::runtime_analyzer::CSourceLooksLikeCxx;
    using coretrace::runtime_analyzer::FindOutputArgument;
    using coretrace::runtime_analyzer::HasCompileOnlyAction;
    using coretrace::runtime_analyzer::HasLanguageOverride;
    using coretrace::runtime_analyzer::MakeTestOutputPath;
    using coretrace::runtime_analyzer::OutputFormat;
    using coretrace::runtime_analyzer::ParseArgs;
    using coretrace::runtime_analyzer::ParseResult;
    using coretrace::runtime_analyzer::SanitizeArtifactName;
    using coretrace::runtime_analyzer::SourceRequiresDebugDefine;
    using unittests::Expect;

    using Args = std::vector<std::string>;

    [[nodiscard]] ParseResult Parse(Args args)
    {
        args.insert(args.begin(), "runtime-analyzer");
        std::vector<char*> argv;
        for (std::string& arg : args)
        {
            argv.push_back(arg.data());
        }
        return ParseArgs(static_cast<int>(argv.size()), argv.data());
    }

    [[nodiscard]] std::filesystem::path Source(std::string_view name, std::string_view text)
    {
        const std::filesystem::path path = std::filesystem::temp_directory_path() / name;
        std::ofstream(path) << text;
        return path;
    }

    void EveryOptionLandsInTheOptions()
    {
        const ParseResult parsed = Parse({"-o",
                                          "bin",
                                          "--run-arg",
                                          "one",
                                          "--run-arg",
                                          "two",
                                          "--env",
                                          "A=1",
                                          "--cwd",
                                          "dir",
                                          "--timeout",
                                          "5",
                                          "--test-dir",
                                          "t1",
                                          "--test-dir",
                                          "t2",
                                          "--output-dir",
                                          "out",
                                          "--strict-test-exit",
                                          "--no-run",
                                          "--show-output",
                                          "--show-events",
                                          "--format=sarif",
                                          "--",
                                          "--ct-modules=alloc",
                                          "main.c"});
        Expect(parsed.ok && !parsed.help && !parsed.version, "all options: parsed");
        const AnalyzerOptions& o = parsed.options;
        Expect(o.output_path == "bin" && o.explicit_output_path, "all options: -o");
        Expect(o.program_args == Args{"one", "two"}, "all options: --run-arg, repeatable");
        Expect(o.environment == Args{"A=1"}, "all options: --env");
        Expect(o.working_directory == "dir", "all options: --cwd");
        Expect(o.timeout == std::chrono::seconds(5), "all options: --timeout in seconds");
        Expect(o.test_directories == Args{"t1", "t2"}, "all options: --test-dir, repeatable");
        Expect(o.output_directory == "out", "all options: --output-dir");
        Expect(o.strict_test_exit && !o.run_program && o.show_program_output && o.show_events,
               "all options: the flags");
        Expect(parsed.format == OutputFormat::Sarif, "all options: --format=sarif");
        Expect(o.compiler_args == Args{"--ct-modules=alloc", "main.c"},
               "all options: everything after -- is a compiler argument");
    }

    void DefaultsWithoutOptions()
    {
        const ParseResult parsed = Parse({"--", "main.c"});
        const AnalyzerOptions& o = parsed.options;
        Expect(parsed.ok && parsed.format == OutputFormat::Text, "defaults: text output");
        Expect(o.output_path == "runtime-analyzer.out" && !o.explicit_output_path,
               "defaults: the default binary path, not explicit");
        Expect(o.timeout == std::chrono::seconds(60) && o.run_program && !o.strict_test_exit &&
                   !o.show_program_output && !o.show_events,
               "defaults: 60 s, run, no flag");
        Expect(o.output_directory == "runtime-analyzer-artifacts", "defaults: artifact directory");
    }

    void OptionSpellings()
    {
        Expect(Parse({"--output=bin", "--", "a.c"}).options.output_path == "bin",
               "--output=<path>");
        Expect(Parse({"--format", "text", "--", "a.c"}).format == OutputFormat::Text &&
                   Parse({"--format", "sarif", "--", "a.c"}).format == OutputFormat::Sarif,
               "--format <value> as a separate argument");
        Expect(Parse({"--timeout", "0", "--", "a.c"}).options.timeout ==
                   std::chrono::milliseconds(0),
               "--timeout 0 disables the limit");
        Expect(Parse({"-h"}).help && Parse({"--help"}).help, "-h and --help");
        Expect(Parse({"--version"}).version, "--version");
        Expect(Parse({"--test-dir", "t"}).ok, "--test-dir needs no compiler argument");
        Expect(Parse({"--", "-o", "x", "a.c"}).options.compiler_args == Args{"-o", "x", "a.c"},
               "-o after -- belongs to the compiler");
    }

    void InvalidArguments()
    {
        struct Case
        {
            Args args;
            std::string_view message;
        };
        const Case cases[] = {
            {{"--bogus", "--", "a.c"}, "unknown analyzer option: --bogus"},
            {{"-o"}, "-o requires a value"},
            {{"--run-arg"}, "--run-arg requires a value"},
            {{"--env"}, "--env requires NAME=VALUE"},
            {{"--env", "NOVALUE", "--", "a.c"}, "--env requires NAME=VALUE"},
            {{"--env", "=x", "--", "a.c"}, "--env requires NAME=VALUE"},
            {{"--cwd"}, "--cwd requires a path"},
            {{"--timeout"}, "--timeout requires a number of seconds"},
            {{"--timeout", "-1", "--", "a.c"}, "non-negative number of seconds"},
            {{"--timeout", "5x", "--", "a.c"}, "non-negative number of seconds"},
            {{"--test-dir"}, "--test-dir requires a path"},
            {{"--output-dir"}, "--output-dir requires a path"},
            {{"--format"}, "--format requires text or sarif"},
            {{"--format=xml", "--", "a.c"}, "--format requires text or sarif"},
            {{}, "missing compiler arguments"},
            {{"--"}, "missing compiler arguments"},
        };
        for (const Case& c : cases)
        {
            const ParseResult parsed = Parse(c.args);
            Expect(!parsed.ok && parsed.error.find(c.message) != std::string::npos,
                   "invalid: " + std::string(c.message));
        }
    }

    void OutputArgumentOfTheCompiler()
    {
        Expect(!FindOutputArgument({"a.c"}).present, "no -o: absent");
        Expect(FindOutputArgument({"-o", "x", "a.c"}).path == "x", "-o x");
        Expect(FindOutputArgument({"--output", "x"}).path == "x", "--output x");
        Expect(FindOutputArgument({"-o=x"}).path == "x", "-o=x");
        Expect(FindOutputArgument({"--output=x"}).path == "x", "--output=x");
        const auto last = FindOutputArgument({"a.c", "-o"});
        Expect(last.present && last.path.empty(), "-o as the last argument: present, no path");
    }

    void CompileOnlyAndLanguageFlags()
    {
        for (const char* flag : {"-c", "-S", "-E", "-emit-llvm", "--precompile", "-fsyntax-only"})
        {
            Expect(HasCompileOnlyAction({"a.c", flag}), std::string("compile only: ") + flag);
        }
        Expect(!HasCompileOnlyAction({"-O2", "a.c"}), "compile only: not with -O2");
        Expect(HasLanguageOverride({"-x", "c++", "a.c"}) && HasLanguageOverride({"-xc++"}) &&
                   HasLanguageOverride({"-x=c++"}),
               "language override: -x c++, -xc++, -x=c++");
        Expect(!HasLanguageOverride({"-O2", "a.c"}), "language override: none");
    }

    void SourceHeuristics()
    {
        Expect(CSourceLooksLikeCxx("a.c", "#include <string>\nint main() { std::string s; }"),
               "a .c using std:: is C++");
        Expect(!CSourceLooksLikeCxx("a.c", "int main(void) { return 0; }"), "plain C is C");
        Expect(!CSourceLooksLikeCxx("a.cpp", "std::string s;"), "a .cpp needs no override");
        Expect(SourceRequiresDebugDefine("#ifndef DEBUG\n#error x\n#endif") &&
                   SourceRequiresDebugDefine("#if !defined(DEBUG)"),
               "DEBUG guard: #ifndef and #if !defined");
        Expect(!SourceRequiresDebugDefine("int main(void) { return 0; }"), "DEBUG guard: none");

        Args args{"-O1"};
        AddPerSourceCompatibilityArgs(Source("cli_args_cxx.c", "std::string s;"), args);
        Expect(args == Args{"-O1", "-x", "c++"}, "compat: -x c++ added for C that is C++");
        args = {"-x", "c"};
        AddPerSourceCompatibilityArgs(Source("cli_args_cxx.c", "std::string s;"), args);
        Expect(args == Args{"-x", "c"}, "compat: the user's -x is kept");
        args = {};
        AddPerSourceCompatibilityArgs(Source("cli_args_debug.c", "#ifndef DEBUG\n#endif"), args);
        Expect(args == Args{"-DDEBUG"}, "compat: -DDEBUG added for a DEBUG guard");
        args = {"-DDEBUG=1"};
        AddPerSourceCompatibilityArgs(Source("cli_args_debug.c", "#ifndef DEBUG\n#endif"), args);
        Expect(args == Args{"-DDEBUG=1"}, "compat: the user's -DDEBUG is kept");
        args = {};
        AddPerSourceCompatibilityArgs(Source("cli_args_plain.c", "int main(void){}"), args);
        Expect(args.empty(), "compat: nothing for plain C");
    }

    void CompilerArguments()
    {
        AnalyzerOptions options;
        options.compiler_args = {"--instrument", "--ct-modules=alloc", "a.c"};
        options.output_path = "bin";
        std::string output;
        Expect(BuildCompilerArguments(options, output) ==
                       Args{"--ct-modules=alloc", "a.c", "-o", "bin"} &&
                   output == "bin",
               "compiler arguments: --instrument dropped, -o appended");
        options.compiler_args = {"a.c", "-o", "theirs"};
        Expect(BuildCompilerArguments(options, output) == Args{"a.c", "-o", "theirs"} &&
                   output == "theirs",
               "compiler arguments: the compiler's -o is kept and reported");
        options.compiler_args = {"a.c"};
        options.output_path.clear();
        (void)BuildCompilerArguments(options, output);
        Expect(output == "runtime-analyzer.out", "compiler arguments: the default binary path");
    }

    void ArtifactNames()
    {
        Expect(SanitizeArtifactName("dir/sub/a b.c") == "dir_sub_a_b_c",
               "artifact name: only letters, digits, - and _ survive");
        Expect(SanitizeArtifactName("") == "test", "artifact name: 'test' for an empty path");

        AnalyzerOptions options;
        options.output_directory = "out";
        const std::filesystem::path first = MakeTestOutputPath(options, "dir/a.c");
        const std::string name = first.filename().string();
        Expect(first.parent_path() == "out" && name.rfind("dir_a_", 0) == 0 &&
                   name.size() == std::string("dir_a_").size() + 16,
               "artifact path: <output dir>/<sanitized stem>_<16 hex digits>");
        Expect(MakeTestOutputPath(options, "dir/a.c") == first, "artifact path: stable");
        Expect(MakeTestOutputPath(options, "dir/b.c") != first &&
                   MakeTestOutputPath(options, "other/a.c") != first,
               "artifact path: distinct sources get distinct paths");
    }
} // namespace

int main()
{
    EveryOptionLandsInTheOptions();
    DefaultsWithoutOptions();
    OptionSpellings();
    InvalidArguments();
    OutputArgumentOfTheCompiler();
    CompileOnlyAndLanguageFlags();
    SourceHeuristics();
    CompilerArguments();
    ArtifactNames();
    return unittests::Finish("cli_args_test");
}
