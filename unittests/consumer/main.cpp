// SPDX-License-Identifier: Apache-2.0
// Analyzes one program through the library and prints its findings, one "rule CWE" per line.
#include <runtime_analyzer.hpp>

#include <iostream>

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        std::cerr << "usage: consumer <source> <output binary>\n";
        return 2;
    }
    coretrace::runtime_analyzer::AnalyzerOptions options;
    options.compiler_args = {"--ct-modules=alloc,bounds", argv[1]};
    options.output_path = argv[2];
    options.explicit_output_path = true;
    const coretrace::runtime_analyzer::AnalyzerResult result =
        coretrace::runtime_analyzer::Run(options);
    std::cerr << result.diagnostics;
    for (const coretrace::runtime_analyzer::Finding& finding : result.findings)
    {
        std::cout << finding.rule << ' ' << finding.cwe << '\n';
    }
    return result.compile_success && result.executed ? 0 : 1;
}
