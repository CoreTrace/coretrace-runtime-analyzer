#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""No program can keep runtime-analyzer waiting past --timeout.

Usage: check_timeout.py <runtime-analyzer> <work dir>

The programs are written into the work directory: they must not live under test/, which the
sweep tests run in full.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

PROGRAMS = {
    "hang.c": "#include <unistd.h>\nint main(void)\n{\n    for (;;)\n        pause();\n}\n",
    "stdin_eof.c": "#include <stdio.h>\nint main(void)\n{\n    while (getchar() != EOF)\n"
                   "    {\n    }\n    return 0;\n}\n",
    # The parent exits at once; its child keeps stdout open while it sleeps.
    "fork_child.c": "#include <unistd.h>\nint main(void)\n{\n    if (fork() == 0)\n"
                    "        sleep(30);\n    return 0;\n}\n",
    "normal.c": "int main(void)\n{\n    return 0;\n}\n",
}

failures = 0


def expect(condition: bool, message: str) -> None:
    global failures
    print(("[PASS] " if condition else "[FAIL] ") + message)
    if not condition:
        failures += 1


def run(analyzer: str, *args: str, cwd: Path) -> tuple[subprocess.CompletedProcess | None, float]:
    started = time.monotonic()
    try:
        completed = subprocess.run([analyzer, *args], cwd=cwd, capture_output=True, text=True,
                                   timeout=60, stdin=subprocess.PIPE)
    except subprocess.TimeoutExpired:
        return None, time.monotonic() - started
    return completed, time.monotonic() - started


def main() -> int:
    analyzer, work = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
    programs = work / "programs"
    batch = work / "batch"
    for directory in (programs, batch):
        directory.mkdir(parents=True, exist_ok=True)
    for name, source in PROGRAMS.items():
        (programs / name).write_text(source)
    for name in ("hang.c", "normal.c"):
        (batch / name).write_text(PROGRAMS[name])
    modules = "--ct-modules=alloc"

    completed, elapsed = run(analyzer, "--timeout", "1", "-o", str(work / "hang"), "--", modules,
                             "hang.c", cwd=programs)
    expect(completed is not None and completed.returncode == 2,
           "hang.c: exit 2, the program was not analyzed to completion")
    expect(elapsed < 10, f"hang.c: the analyzer returned within a few seconds ({elapsed:.1f}s)")
    expect(completed is not None and "timed out after 1 s" in completed.stderr,
           "hang.c: the diagnostics mention the timeout")
    expect(completed is not None and "runtime-analyzer: timed_out=1" in completed.stdout,
           "hang.c: the summary reports timed_out")

    completed, elapsed = run(analyzer, "-o", str(work / "stdin_eof"), "--", modules,
                             "stdin_eof.c", cwd=programs)
    expect(completed is not None and completed.returncode == 0,
           "stdin_eof.c: exit 0, stdin is /dev/null so the program ends at EOF")

    completed, elapsed = run(analyzer, "--timeout", "1", "-o", str(work / "fork_child"), "--",
                             modules, "fork_child.c", cwd=programs)
    expect(completed is not None and elapsed < 10,
           f"fork_child.c: the analyzer returned although a child kept stdout open ({elapsed:.1f}s)")

    completed, elapsed = run(analyzer, "--test-dir", ".", "--timeout", "1", "--output-dir",
                             str(work / "batch-artifacts"), "--", modules, cwd=batch)
    expect(completed is not None and elapsed < 10, f"batch: completes ({elapsed:.1f}s)")
    expect(completed is not None and "runtime-analyzer: [TIMEOUT] ./hang.c" in completed.stdout,
           "batch: the hung program is marked [TIMEOUT]")
    expect(completed is not None and "runtime-analyzer: [PASS] ./normal.c" in completed.stdout,
           "batch: the other program is still reported")
    expect(completed is not None and "  timeouts=1\n" in completed.stdout,
           "batch: the summary counts the timeouts")
    expect(completed is not None and completed.returncode == 2, "batch: exit 2 with a timeout")

    completed, _ = run(analyzer, "--timeout", "x", "--", modules, "normal.c", cwd=programs)
    expect(completed is not None and completed.returncode == 2, "--timeout x: exit 2")

    if failures:
        print(f"{failures} timeout check(s) failed", file=sys.stderr)
        return 1
    print("check_timeout: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
