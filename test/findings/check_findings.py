#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Each runtime memory error becomes one finding with its rule, CWE and source location.

Usage: check_findings.py <runtime-analyzer> <work dir>
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

# fixture: (rule, CWE, SARIF level, faulting access line, allocation line). A stack object's
# allocation line is its function's; a leak has no faulting access.
MEMORY_ARGS = ["--ct-modules=alloc,bounds"]
EXPECTED = {
    "heap_overflow_write.c": ("heap-buffer-overflow", "CWE-122", "error", 7, 6),
    "heap_overflow_read.c": ("heap-buffer-overflow", "CWE-125", "error", 7, 6),
    "stack_overflow_write.c": ("stack-buffer-overflow", "CWE-121", "error", 7, 3),
    "use_after_free.c": ("heap-use-after-free", "CWE-416", "error", 8, 6),
    "double_free.c": ("double-free", "CWE-415", "error", 8, 6),
    "memory_leak.c": ("memory-leak", "CWE-401", "warning", None, 6),
}

# The vtable module's diagnostics, over the fixtures at the root of test/. The boxes carry no
# allocation site.
VTABLE_ARGS = ["--ct-modules=alloc,vtable", "--ct-vtable-diag"]
VTABLE_EXPECTED = {
    "ct_vtable_diag_null.cpp": ("vtable-null-this", "CWE-476", "error", 7),
    "ct_vtable_diag_freed.cpp": ("vtable-use-after-free", "CWE-416", "error", 22),
    "ct_vtable_diag_stack_target.cpp": ("vcall-invalid-target", "CWE-843", "error", 25),
    "ct_vtable_diag_mismatch.cpp": ("vtable-type-mismatch", "CWE-843", "warning", 24),
    "ct_vtable_diag_fake.cpp": ("vtable-corrupted", "CWE-843", "error", 22),
}

failures = 0


def expect(condition: bool, message: str) -> None:
    global failures
    print(("[PASS] " if condition else "[FAIL] ") + message)
    if not condition:
        failures += 1


def analyze(analyzer: str, work: Path, fixture: str, *options: str,
            compiler_args: list[str] = MEMORY_ARGS, source: str | None = None
            ) -> subprocess.CompletedProcess:
    # Run from test/ with a relative source: the finding must carry the path the source was
    # compiled from, as the static analyzers report it.
    return subprocess.run(
        [analyzer, "-o", str(work / Path(fixture).stem), *options, "--", *compiler_args,
         source or f"findings/{fixture}"],
        cwd=HERE.parent,
        capture_output=True,
        text=True,
        timeout=120,
    )


def region(location: dict) -> tuple[str, int, int]:
    physical = location["physicalLocation"]
    return (
        physical["artifactLocation"]["uri"],
        physical["region"]["startLine"],
        physical["region"].get("startColumn", 0),
    )


def sarif_results(completed: subprocess.CompletedProcess, fixture: str) -> list[dict] | None:
    try:
        log = json.loads(completed.stdout)
    except json.JSONDecodeError:
        expect(False, f"{fixture}: stdout is a JSON document\n{completed.stdout}{completed.stderr}")
        return None
    expect(log.get("version") == "2.1.0", f"{fixture}: SARIF 2.1.0")
    expect(log["runs"][0]["tool"]["driver"]["name"] == "coretrace-runtime-analyzer",
           f"{fixture}: tool name")
    return log["runs"][0]["results"]


def main() -> int:
    analyzer, work = str(Path(sys.argv[1]).resolve()), Path(sys.argv[2]).resolve()
    work.mkdir(parents=True, exist_ok=True)

    for fixture, (rule, cwe, level, access_line, alloc_line) in EXPECTED.items():
        completed = analyze(analyzer, work, fixture, "--format=sarif")
        expect(completed.returncode == 1, f"{fixture}: exit 1 when findings are reported")
        results = sarif_results(completed, fixture) or []
        expect(len(results) == 1, f"{fixture}: exactly one finding (got {len(results)})")
        if len(results) != 1:
            continue
        result = results[0]
        expect(result.get("ruleId") == rule, f"{fixture}: rule {rule}")
        expect(result.get("properties", {}).get("cwe") == cwe, f"{fixture}: {cwe}")
        expect(result.get("level") == level, f"{fixture}: level {level}")
        expect(bool(result.get("message", {}).get("text")), f"{fixture}: has a message")
        if access_line is None:
            expect("locations" not in result, f"{fixture}: no faulting access")
        else:
            uri, line, column = region(result["locations"][0])
            expect(uri == f"findings/{fixture}", f"{fixture}: located in the compiled source")
            expect(line == access_line and column > 0,
                   f"{fixture}: faulting access at line {access_line} (got {line}:{column})")
        related = result.get("relatedLocations", [{}])[0]
        uri, line, _ = region(related) if related else ("", 0, 0)
        expect(uri == f"findings/{fixture}" and line == alloc_line,
               f"{fixture}: allocation site at line {alloc_line} (got {uri}:{line})")
        expect(related.get("id") == 0 and related.get("message", {}).get("text") == "allocated here",
               f"{fixture}: allocation site is related location 0, 'allocated here'")

    for fixture, (rule, cwe, level, line) in VTABLE_EXPECTED.items():
        completed = analyze(analyzer, work, fixture, "--format=sarif",
                            compiler_args=VTABLE_ARGS, source=fixture)
        expect(completed.returncode == 1, f"{fixture}: exit 1 when findings are reported")
        results = sarif_results(completed, fixture) or []
        expect(len(results) == 1, f"{fixture}: exactly one finding (got {len(results)})")
        if len(results) != 1:
            continue
        result = results[0]
        expect(result.get("ruleId") == rule, f"{fixture}: rule {rule}")
        expect(result.get("properties", {}).get("cwe") == cwe, f"{fixture}: {cwe}")
        expect(result.get("level") == level, f"{fixture}: level {level}")
        uri, got_line, column = region(result["locations"][0])
        expect(uri == fixture and got_line == line and column > 0,
               f"{fixture}: site at line {line} (got {uri}:{got_line}:{column})")
        expect("relatedLocations" not in result, f"{fixture}: no allocation site")

    completed = analyze(analyzer, work, "ct_vtable_basic.cpp", "--format=sarif",
                        compiler_args=VTABLE_ARGS, source="ct_vtable_basic.cpp")
    expect(completed.returncode == 0 and sarif_results(completed, "ct_vtable_basic.cpp") == [],
           "ct_vtable_basic.cpp: tracing boxes are not findings")

    # The program's exit status is reported, but only runtime errors decide the verdict.
    completed = analyze(analyzer, work, "no_findings.c", "--format=sarif")
    expect(completed.returncode == 0, "no_findings.c: exit 0 without findings")
    expect(sarif_results(completed, "no_findings.c") == [], "no_findings.c: no finding")
    completed = analyze(analyzer, work, "no_findings.c")
    expect(completed.returncode == 0 and "runtime-analyzer: exit_code=3" in completed.stdout,
           "no_findings.c: the text summary keeps the program's exit code")
    expect("runtime-analyzer: findings=0" in completed.stdout, "no_findings.c: findings=0 in text")

    completed = analyze(analyzer, work, "heap_overflow_write.c")
    expect(completed.returncode == 1, "text output: exit 1 with findings")
    expect("runtime-analyzer: findings=1" in completed.stdout, "text output: findings=1")
    expect("findings/heap_overflow_write.c:7:" in completed.stdout
           and "error: heap-buffer-overflow WRITE of size 4 [heap-buffer-overflow, CWE-122]"
           in completed.stdout,
           "text output: one compiler-style line per finding")
    expect("findings/heap_overflow_write.c:6:" in completed.stdout
           and "note: allocated here" in completed.stdout,
           "text output: the allocation site as a note")

    completed = analyze(analyzer, work, "no_findings.c", "--no-run", "--format=sarif")
    expect(completed.returncode == 0, "--no-run: exit 0 after a successful build")

    # --test-dir runs every fixture and reports all their findings in one log.
    completed = subprocess.run(
        [analyzer, "--test-dir", "findings", "--output-dir", str(work / "batch"),
         "--format=sarif", "--", *MEMORY_ARGS],
        cwd=HERE.parent, capture_output=True, text=True, timeout=300,
    )
    expect(completed.returncode == 1, "batch: exit 1 when any program reports findings")
    results = sarif_results(completed, "batch") or []
    expect(sorted(result["ruleId"] for result in results) ==
           sorted(expected[0] for expected in EXPECTED.values()),
           "batch: one log with the findings of every program")
    completed = subprocess.run(
        [analyzer, "--test-dir", "findings", "--output-dir", str(work / "batch"),
         "--", *MEMORY_ARGS],
        cwd=HERE.parent, capture_output=True, text=True, timeout=300,
    )
    expect(completed.returncode == 1 and "runtime-analyzer: [PASS] findings/no_findings.c"
           not in completed.stdout and "findings/heap_overflow_write.c:7:" in completed.stdout,
           "batch text: findings are listed under each test's line")

    completed = analyze(analyzer, work, "missing.c")
    expect(completed.returncode == 2, "exit 2 when the program cannot be built")
    completed = analyze(analyzer, work, "no_findings.c", "--format=xml")
    expect(completed.returncode == 2, "exit 2 on an unknown output format")
    completed = subprocess.run(
        [analyzer, "--test-dir", "findings", "--", "-c"],
        cwd=HERE.parent, capture_output=True, text=True, timeout=60,
    )
    expect(completed.returncode == 2, "batch: exit 2 on compile-only flags")

    if failures:
        print(f"{failures} finding check(s) failed", file=sys.stderr)
        return 1
    print("check_findings: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
