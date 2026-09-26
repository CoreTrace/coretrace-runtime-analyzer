#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""A source that fails code generation fails its own analysis, not the analyzer's process.

Usage: check_compile_failure.py <runtime-analyzer> <work dir>

The programs are written into the work directory: they must not live under test/, which the
sweep tests expect to compile in full.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

# Compiles, then fails code generation: no assembler knows this instruction. LLVM reports it
# through its diagnostic handler, which used to end the whole process (coretrace-compiler#91).
CODEGEN_ERROR = (
    "int main(void)\n{\n    __asm__ volatile(\"ct_not_an_instruction\");\n    return 0;\n}\n"
)
NORMAL = "int main(void)\n{\n    return 0;\n}\n"

failures = 0


def expect(condition: bool, message: str) -> None:
    global failures
    print(("[PASS] " if condition else "[FAIL] ") + message)
    if not condition:
        failures += 1


def main() -> int:
    analyzer, work = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
    sources = work / "sources"
    sources.mkdir(parents=True, exist_ok=True)
    (sources / "codegen_error.c").write_text(CODEGEN_ERROR)
    (sources / "normal.c").write_text(NORMAL)

    completed = subprocess.run(
        [analyzer, "-o", str(work / "codegen_error"), "--", "codegen_error.c"],
        cwd=sources, capture_output=True, text=True, timeout=120)
    expect(completed.returncode == 2, "codegen_error.c: exit 2, the program could not be built")
    expect("ct_not_an_instruction" in completed.stderr,
           "codegen_error.c: the code-generation error is in the diagnostics")
    expect("runtime-analyzer: binary=" in completed.stdout,
           "codegen_error.c: the analyzer still prints its summary")

    completed = subprocess.run(
        [analyzer, "--test-dir", ".", "--output-dir", str(work / "batch"), "--"],
        cwd=sources, capture_output=True, text=True, timeout=120)
    expect("runtime-analyzer: [COMPILE] ./codegen_error.c" in completed.stdout,
           "batch: the failing source is reported as [COMPILE]")
    expect("runtime-analyzer: [PASS] ./normal.c" in completed.stdout,
           "batch: the other source is still built and run")
    expect("  compile_failures=1\n" in completed.stdout, "batch: the summary counts the failure")
    expect(completed.returncode == 2, "batch: exit 2 with a source that could not be built")

    if failures:
        print(f"{failures} compile failure check(s) failed", file=sys.stderr)
        return 1
    print("check_compile_failure: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
