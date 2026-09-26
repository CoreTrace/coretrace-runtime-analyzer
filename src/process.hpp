// SPDX-License-Identifier: Apache-2.0
#ifndef CORETRACE_RUNTIME_ANALYZER_PROCESS_HPP
#define CORETRACE_RUNTIME_ANALYZER_PROCESS_HPP

#include <chrono>
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
        std::chrono::milliseconds timeout{0}; // 0 waits for the program without limit
    };

    struct ProcessResult
    {
        int exit_code = 1; // 128 + signal when the process was killed
        std::string stdout_text;
        std::string stderr_text;
        std::string error;      // why the process could not be run; empty when it ran
        bool timed_out = false; // the deadline passed and the process group was killed
    };

    // Runs the program in its own process group with stdin on /dev/null, capturing its stdout
    // and stderr. When the timeout passes, the whole group is killed and the output captured
    // so far is kept.
    [[nodiscard]] ProcessResult RunProcess(const ProcessSpec& spec);
} // namespace coretrace::runtime_analyzer

#endif // CORETRACE_RUNTIME_ANALYZER_PROCESS_HPP
