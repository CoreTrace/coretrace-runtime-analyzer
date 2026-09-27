#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The CLI's options, output formats and verdicts, as the README states them.

Usage: check_cli.py <runtime-analyzer> <work dir>

What each fixture proves is stated in the fixture and checked by check_fixtures.py; this script
checks how the CLI drives a run and reports it: every option, the text output, the SARIF log of
a batch, and exit 2 with a message for what cannot be analyzed. The programs it needs are
written into the work directory: they must not live under test/, which the sweeps run in full.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEST_DIR = HERE.parent
MEMORY_ARGS = ["--ct-modules=alloc,bounds"]

PROGRAMS = {
    "args.c": "#include <stdio.h>\nint main(int argc, char** argv)\n{\n    printf(\"argc=%d\\n\", argc);\n"
              "    for (int i = 1; i < argc; ++i)\n        puts(argv[i]);\n    return 0;\n}\n",
    "env.c": "#include <stdio.h>\n#include <stdlib.h>\nint main(void)\n{\n"
             "    const char* value = getenv(\"CT_CHECK\");\n"
             "    printf(\"CT_CHECK=%s\\n\", value ? value : \"(unset)\");\n    return 0;\n}\n",
    "cwd.c": "#include <stdio.h>\n#include <unistd.h>\nint main(void)\n{\n    char buffer[4096];\n"
             "    puts(getcwd(buffer, sizeof buffer));\n    return 0;\n}\n",
    "chatty.c": "#include <stdio.h>\nint main(void)\n{\n    puts(\"to-stdout\");\n"
                "    fputs(\"to-stderr\\n\", stderr);\n    return 0;\n}\n",
    "exit_one.c": "int main(void)\n{\n    return 1;\n}\n",
    "normal.c": "int main(void)\n{\n    return 0;\n}\n",
}

failures = 0


def expect(condition: bool, message: str) -> None:
    global failures
    print(f"[{'PASS' if condition else 'FAIL'}] {message}")
    if not condition:
        failures += 1


def run(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    # From test/, with relative sources: findings carry the path the source was compiled from.
    return subprocess.run(list(args), cwd=TEST_DIR, capture_output=True, text=True,
                          timeout=timeout)


def analyze(analyzer: str, work: Path, fixture: str, *options: str) -> subprocess.CompletedProcess:
    return run(analyzer, "-o", str(work / Path(fixture).stem), *options, "--", *MEMORY_ARGS,
               f"findings/{fixture}")


def sarif_rules(completed: subprocess.CompletedProcess) -> list[str] | None:
    try:
        log = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None
    return sorted(result["ruleId"] for result in log["runs"][0]["results"])


def program(analyzer: str, work: Path, name: str, *options: str) -> subprocess.CompletedProcess:
    return run(analyzer, "-o", str(work / Path(name).stem), *options, "--", *MEMORY_ARGS,
               str(work / name))


def check_options(analyzer: str, work: Path) -> None:
    completed = program(analyzer, work, "args.c", "--show-output", "--run-arg", "one",
                        "--run-arg", "two words")
    expect(completed.returncode == 0 and "argc=3\none\ntwo words\n" in completed.stdout,
           "--run-arg: each value is an argument of the program, in order")

    completed = program(analyzer, work, "env.c", "--show-output", "--env", "CT_CHECK=hello")
    expect(completed.returncode == 0 and "CT_CHECK=hello\n" in completed.stdout,
           "--env: the variable is set for the program")
    completed = program(analyzer, work, "env.c", "--show-output")
    expect(completed.returncode == 0 and "CT_CHECK=(unset)\n" in completed.stdout,
           "--env: nothing leaks into the program without it")

    elsewhere = work / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    completed = program(analyzer, work, "cwd.c", "--show-output", "--cwd", str(elsewhere))
    expect(completed.returncode == 0 and f"{elsewhere.resolve()}\n" in completed.stdout,
           "--cwd: the program runs in that directory")
    completed = run(analyzer, "-o", "cwd_relative", "--show-output", "--cwd", str(elsewhere),
                    "--", *MEMORY_ARGS, str(work / "cwd.c"))
    expect(completed.returncode == 0 and f"{elsewhere.resolve()}\n" in completed.stdout,
           "--cwd: a relative -o still names the binary to run")
    Path(TEST_DIR / "cwd_relative").unlink(missing_ok=True)

    completed = program(analyzer, work, "chatty.c", "--show-output")
    expect(completed.returncode == 0
           and "\nruntime-analyzer: stdout\nto-stdout\n" in completed.stdout
           and "\nruntime-analyzer: stderr\nto-stderr\n" in completed.stdout,
           "--show-output: the program's stdout and stderr follow the summary")
    completed = program(analyzer, work, "chatty.c")
    expect(completed.returncode == 0 and "to-stdout" not in completed.stdout
           and "to-stderr" not in completed.stdout + completed.stderr,
           "without --show-output: the program's output is not printed")

    completed = analyze(analyzer, work, "no_findings.c", "--show-events")
    expect(completed.returncode == 0 and "\nruntime-analyzer: events\n" in completed.stdout
           and "tracing-malloc" in completed.stdout,
           "--show-events: the CoreTrace event lines follow the summary")
    completed = analyze(analyzer, work, "no_findings.c")
    expect("runtime-analyzer: events" not in completed.stdout
           and "tracing-malloc" not in completed.stdout,
           "without --show-events: the event lines are not printed")

    completed = program(analyzer, work, "normal.c", "--format", "text")
    expect(completed.returncode == 0 and "runtime-analyzer: findings=0" in completed.stdout,
           "--format text: the text summary, as a separate argument")
    completed = program(analyzer, work, "normal.c", "--format", "sarif")
    expect(completed.returncode == 0 and sarif_rules(completed) == [],
           "--format sarif: the SARIF log, as a separate argument")
    completed = run(analyzer, f"--output={work / 'normal_eq'}", "--", *MEMORY_ARGS,
                    str(work / "normal.c"))
    expect(completed.returncode == 0 and (work / "normal_eq").exists(),
           "--output=<path>: the binary path, with an equals sign")

    completed = run(analyzer, "--help")
    expect(completed.returncode == 0 and completed.stdout.startswith("Usage: runtime-analyzer"),
           "--help: usage on stdout, exit 0")


def check_batch_options(analyzer: str, work: Path) -> None:
    batch = work / "batch-options"
    batch.mkdir(exist_ok=True)
    for name in ("exit_one.c", "normal.c"):
        (batch / name).write_text(PROGRAMS[name])
    artifacts = work / "batch-options-artifacts"
    completed = run(analyzer, "--test-dir", str(batch), "--output-dir", str(artifacts), "--",
                    *MEMORY_ARGS, timeout=300)
    expect(completed.returncode == 0, "batch: a program exiting non-zero is not a finding")
    expect(f"runtime-analyzer: [RUNTIME] {batch / 'exit_one.c'} exit_code=1" in completed.stdout
           and f"runtime-analyzer: [PASS] {batch / 'normal.c'} exit_code=0" in completed.stdout,
           "batch: the status of each program is on its line")
    expect("  runtime_failures=1\n" in completed.stdout, "batch: the summary counts it")
    expect(f"binary={artifacts}/" in completed.stdout,
           "--output-dir: the binaries are placed under it")
    completed = run(analyzer, "--test-dir", str(batch), "--output-dir", str(artifacts),
                    "--strict-test-exit", "--", *MEMORY_ARGS, timeout=300)
    expect(completed.returncode == 1, "--strict-test-exit: a non-zero program exit gives exit 1")

    second = work / "batch-options-second"
    second.mkdir(exist_ok=True)
    (second / "normal.c").write_text(PROGRAMS["normal.c"])
    completed = run(analyzer, "--test-dir", str(batch), "--test-dir", str(second),
                    "--output-dir", str(artifacts), "--", *MEMORY_ARGS, timeout=300)
    expect(completed.returncode == 0 and "  tests=3\n" in completed.stdout,
           "--test-dir: repeatable, every directory is run")

    completed = run(analyzer, "--test-dir", str(work / "absent"), "--output-dir", str(artifacts),
                    "--", *MEMORY_ARGS)
    expect(completed.returncode == 2 and "test directory does not exist" in completed.stderr,
           "--test-dir: exit 2 and a message for a directory that does not exist")


def check_invalid_arguments(analyzer: str, work: Path) -> None:
    source = str(work / "normal.c")
    cases = {
        "an unknown option": (["--bogus", "--", source], "unknown analyzer option: --bogus"),
        "--run-arg without a value": (["--run-arg"], "--run-arg requires a value"),
        "--env without a value": (["--env"], "--env requires NAME=VALUE"),
        "--env without NAME=": (["--env", "NOVALUE", "--", source], "--env requires NAME=VALUE"),
        "--env with an empty name": (["--env", "=x", "--", source], "--env requires NAME=VALUE"),
        "--cwd without a value": (["--cwd"], "--cwd requires a path"),
        "--timeout without a value": (["--timeout"], "--timeout requires"),
        "--timeout negative": (["--timeout", "-1", "--", source], "non-negative number"),
        "--test-dir without a value": (["--test-dir"], "--test-dir requires a path"),
        "--output-dir without a value": (["--output-dir"], "--output-dir requires a path"),
        "--format without a value": (["--format"], "--format requires text or sarif"),
        "no compiler arguments": ([], "missing compiler arguments"),
        "-- without compiler arguments": (["--"], "missing compiler arguments"),
    }
    for what, (args, message) in cases.items():
        completed = run(analyzer, *args)
        expect(completed.returncode == 2 and message in completed.stderr
               and "Usage: runtime-analyzer" in completed.stderr,
               f"{what}: exit 2, the message and the usage on stderr")

    # "-o" as the last argument after -- is a compiler argument: the compiler rejects it.
    completed = run(analyzer, "-o")
    expect(completed.returncode == 2 and "-o requires a value" in completed.stderr,
           "-o as the last argument: exit 2 and the message")
    completed = run(analyzer, "-o", str(work / "twice"), "--", *MEMORY_ARGS, "-o",
                    str(work / "twice2"), source)
    expect(completed.returncode == 2 and "output path specified twice" in completed.stderr,
           "-o with a compiler -o: exit 2 and the message")


def main() -> int:
    analyzer, work = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
    work.mkdir(parents=True, exist_ok=True)
    for name, text in PROGRAMS.items():
        (work / name).write_text(text)
    check_options(analyzer, work)
    check_batch_options(analyzer, work)
    check_invalid_arguments(analyzer, work)

    # The program's exit status is reported, but only runtime errors decide the verdict.
    completed = analyze(analyzer, work, "no_findings.c")
    expect(completed.returncode == 0 and "runtime-analyzer: exit_code=3" in completed.stdout,
           "no_findings.c: the text summary keeps the program's exit code")
    expect("runtime-analyzer: findings=0" in completed.stdout, "no_findings.c: findings=0 in text")

    completed = analyze(analyzer, work, "heap_overflow_write.c")
    expect(completed.returncode == 1, "text output: exit 1 with findings")
    expect("runtime-analyzer: findings=1" in completed.stdout, "text output: findings=1")
    expect("findings/heap_overflow_write.c:8:" in completed.stdout
           and "error: heap-buffer-overflow WRITE of size 4 [heap-buffer-overflow, CWE-122]"
           in completed.stdout,
           "text output: one compiler-style line per finding")
    expect("findings/heap_overflow_write.c:7:" in completed.stdout
           and "note: allocated here" in completed.stdout,
           "text output: the allocation site as a note")

    completed = analyze(analyzer, work, "no_findings.c", "--no-run", "--format=sarif")
    expect(completed.returncode == 0 and sarif_rules(completed) == [],
           "--no-run: exit 0 and an empty log after a successful build")

    # --test-dir runs every fixture and reports all their findings in one log.
    completed = run(analyzer, "--test-dir", "findings", "--output-dir", str(work / "batch"),
                    "--format=sarif", "--", *MEMORY_ARGS, timeout=300)
    expect(completed.returncode == 1, "batch: exit 1 when any program reports findings")
    expect(sarif_rules(completed) == ["double-free", "heap-buffer-overflow", "heap-buffer-overflow",
                                      "heap-use-after-free", "memory-leak", "stack-buffer-overflow"],
           "batch: one log with the findings of every program")
    completed = run(analyzer, "--test-dir", "findings", "--output-dir", str(work / "batch"),
                    "--", *MEMORY_ARGS, timeout=300)
    expect(completed.returncode == 1 and "runtime-analyzer: [PASS] findings/no_findings.c"
           not in completed.stdout and "findings/heap_overflow_write.c:8:" in completed.stdout,
           "batch text: findings are listed under each test's line")

    completed = analyze(analyzer, work, "missing.c")
    expect(completed.returncode == 2, "exit 2 when the program cannot be built")
    completed = analyze(analyzer, work, "no_findings.c", "--format=xml")
    expect(completed.returncode == 2, "exit 2 on an unknown output format")
    completed = run(analyzer, "--test-dir", "findings", "--", "-c", timeout=60)
    expect(completed.returncode == 2, "batch: exit 2 on compile-only flags")

    if failures:
        print(f"{failures} CLI check(s) failed", file=sys.stderr)
        return 1
    print("check_cli: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
