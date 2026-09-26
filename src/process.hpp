// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_PROCESS_HPP
#define CORETRACE_RUNTIME_ANALYZER_PROCESS_HPP

#include <string>
#include <vector>

namespace coretrace::runtime_analyzer
{
    struct ProcessSpec
    {
        std::string executable;
        std::vector<std::string> args;        // argv[1..]
        std::vector<std::string> environment; // NAME=VALUE, set over the inherited environment
        std::string working_directory;        // empty keeps the current one
    };

    struct ProcessResult
    {
        int exit_code = 1; // 128 + signal when the process was killed
        std::string stdout_text;
        std::string stderr_text;
        std::string error; // why the process could not be run; empty when it ran
    };

    // Runs the program, capturing its stdout and stderr, and waits for it to end.
    [[nodiscard]] ProcessResult RunProcess(const ProcessSpec& spec);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_PROCESS_HPP
