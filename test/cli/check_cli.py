#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The CLI's output formats, verdicts and batch mode over the findings fixtures.

Usage: check_cli.py <runtime-analyzer> <work dir>

What each fixture proves is stated in the fixture and checked by check_fixtures.py; this script
checks how the CLI reports it: the text output, the SARIF log of a batch, and the exit status
of the runs that cannot be analyzed.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEST_DIR = HERE.parent
MEMORY_ARGS = ["--ct-modules=alloc,bounds"]

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


def main() -> int:
    analyzer, work = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
    work.mkdir(parents=True, exist_ok=True)

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
