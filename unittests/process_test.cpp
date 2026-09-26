// SPDX-License-Identifier: Apache-2.0
// Checks the process runner on small shell commands.
#include "process.hpp"

#include <chrono>
#include <iostream>
#include <string_view>

namespace
{
    using coretrace::runtime_analyzer::ProcessResult;
    using coretrace::runtime_analyzer::ProcessSpec;
    using coretrace::runtime_analyzer::RunProcess;

    int failures = 0;

    void Expect(bool condition, std::string_view what)
    {
        std::cout << (condition ? "[PASS] " : "[FAIL] ") << what << '\n';
        if (!condition)
        {
            ++failures;
        }
    }

    [[nodiscard]] ProcessSpec Shell(std::string script)
    {
        return ProcessSpec{"/bin/sh", {"-c", std::move(script)}};
    }

    void CapturesOutputAndStatus()
    {
        const ProcessResult result = RunProcess(Shell("echo out; echo err >&2; exit 3"));
        Expect(result.error.empty(), "shell: ran");
        Expect(result.exit_code == 3, "shell: exit status");
        Expect(result.stdout_text == "out\n", "shell: stdout captured");
        Expect(result.stderr_text == "err\n", "shell: stderr captured");
    }

    void StdinIsDevNull()
    {
        const ProcessResult result = RunProcess(
            Shell("if [ /dev/stdin -ef /dev/null ]; then echo null; else echo other; fi"));
        Expect(result.stdout_text == "null\n", "stdin: the program reads /dev/null");
    }

    void TimeoutKillsAHungProgram()
    {
        ProcessSpec spec = Shell("sleep 5");
        spec.timeout = std::chrono::milliseconds(300);
        const auto started = std::chrono::steady_clock::now();
        const ProcessResult result = RunProcess(spec);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        Expect(result.error.empty(), "timeout: ran");
        Expect(result.timed_out, "timeout: reported");
        Expect(elapsed < std::chrono::seconds(3), "timeout: returned before the program ended");
        Expect(result.exit_code == 128 + 9, "timeout: killed with SIGKILL");
    }

    void TimeoutKeepsTheOutputSoFar()
    {
        ProcessSpec spec = Shell("echo before; sleep 5; echo after");
        spec.timeout = std::chrono::milliseconds(300);
        const ProcessResult result = RunProcess(spec);
        Expect(result.timed_out && result.stdout_text == "before\n",
               "timeout: output printed before the deadline is kept");
    }

    void TimeoutKillsTheWholeProcessGroup()
    {
        // The shell exits at once; its child keeps the stdout pipe open.
        ProcessSpec spec = Shell("sleep 5 & exit 0");
        spec.timeout = std::chrono::milliseconds(300);
        const auto started = std::chrono::steady_clock::now();
        const ProcessResult result = RunProcess(spec);
        const auto elapsed = std::chrono::steady_clock::now() - started;
        Expect(result.error.empty(), "group: ran");
        Expect(elapsed < std::chrono::seconds(3), "group: returned once the group was killed");
    }

    void NoTimeoutWaitsForTheProgram()
    {
        const ProcessResult result = RunProcess(Shell("sleep 0.5; echo done"));
        Expect(!result.timed_out && result.stdout_text == "done\n",
               "no timeout: waits for the program");
    }
} // namespace

int main()
{
    CapturesOutputAndStatus();
    StdinIsDevNull();
    TimeoutKillsAHungProgram();
    TimeoutKeepsTheOutputSoFar();
    TimeoutKillsTheWholeProcessGroup();
    NoTimeoutWaitsForTheProgram();
    if (failures != 0)
    {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "process_test: all checks passed\n";
    return 0;
}
