#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every fixture under test/ states what it proves, and the analyzer proves it.

Usage: check_fixtures.py <runtime-analyzer> <test dir> <work dir>

A fixture is a C or C++ source under the test directory. The comments at its top declare:

    // args: --ct-modules=alloc,vtable --ct-vtable-diag
    // expect: rule=heap-buffer-overflow cwe=CWE-122 level=error line=8 alloc=7
    // expect: none
    // expect: program-exit=3
    // expect: output="auto-free ptr="

`args` are the compiler arguments, `--ct-modules=alloc,bounds` by default. One `expect: rule=`
line per finding: `line` is the faulting access and `alloc` the allocation site, both in the
fixture; `cwe` and `level` are checked when given. `expect: none` states that nothing is
reported. `program-exit` is the program's own exit status and `output` a substring of what it
printed. `expect[linux]:` and `expect[darwin]:` keep a line to one platform. The analyzer's exit
status must be 1 with findings and 0 without. A fixture without `expect:` fails: nobody adds
one without saying what it proves.
"""

from __future__ import annotations

import json
import shlex
import subprocess
import sys
from pathlib import Path

DEFAULT_ARGS = ["--ct-modules=alloc,bounds"]
PLATFORM = "darwin" if sys.platform == "darwin" else "linux"
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx"}
KEYS = {"rule", "cwe", "level", "line", "alloc", "program-exit", "output"}

failures = 0


def fail(message: str) -> None:
    global failures
    failures += 1
    print(f"[FAIL] {message}")


def read_header(fixture: Path) -> tuple[list[str], list[dict[str, str]], list[str]]:
    """The compiler arguments, the expectations and the parse errors of a fixture."""
    args, expectations, errors = list(DEFAULT_ARGS), [], []
    for line in fixture.read_text().splitlines():
        if not line.startswith("//"):
            if line.strip():
                break
            continue
        text = line[2:].strip()
        if text.startswith("args:"):
            args = shlex.split(text[len("args:"):])
            continue
        if not text.startswith("expect"):
            continue
        directive, _, rest = text.partition(":")
        platform = directive[len("expect"):].strip("[]")
        if platform not in ("", PLATFORM):
            continue
        tokens = shlex.split(rest)
        if tokens == ["none"]:
            expectations.append({"none": ""})
            continue
        expectation = dict(token.partition("=")[::2] for token in tokens)
        unknown = set(expectation) - KEYS
        if unknown or any("=" not in token for token in tokens):
            errors.append(f"cannot read expectation: {rest.strip()}")
            continue
        expectations.append(expectation)
    return args, expectations, errors


def sarif_findings(stdout: str) -> list[dict[str, object]] | None:
    try:
        log = json.loads(stdout)
    except json.JSONDecodeError:
        return None
    findings = []
    for result in log["runs"][0]["results"]:
        finding: dict[str, object] = {"rule": result["ruleId"], "cwe": result["properties"]["cwe"],
                                      "level": result["level"]}
        for key, locations in (("line", result.get("locations")),
                               ("alloc", result.get("relatedLocations"))):
            if locations:
                physical = locations[0]["physicalLocation"]
                finding[key] = str(physical["region"]["startLine"])
                finding[key + "_uri"] = physical["artifactLocation"]["uri"]
                finding[key + "_column"] = physical["region"].get("startColumn", 0)
        related = (result.get("relatedLocations") or [{}])[0]
        finding["alloc_ok"] = related.get("id") == 0 and \
            related.get("message", {}).get("text") == "allocated here"
        findings.append(finding)
    return findings


def matches(expected: dict[str, str], finding: dict[str, object], uri: str) -> bool:
    for key in ("rule", "cwe", "level", "line", "alloc"):
        if key in expected and finding.get(key) != expected[key]:
            return False
    if "line" in expected and (finding["line_uri"] != uri or not finding["line_column"]):
        return False
    if "alloc" in expected and (finding["alloc_uri"] != uri or not finding["alloc_ok"]):
        return False
    return True


def describe(finding: dict[str, object]) -> str:
    return " ".join(f"{key}={finding[key]}" for key in ("rule", "cwe", "level", "line", "alloc")
                    if key in finding)


def check(analyzer: str, test_dir: Path, work: Path, fixture: Path) -> None:
    rel = fixture.relative_to(test_dir).as_posix()
    args, expectations, errors = read_header(fixture)
    for error in errors:
        fail(f"{rel}: {error}")
    findings_expected = [e for e in expectations if "rule" in e]
    if not findings_expected and not any("none" in e for e in expectations):
        fail(f"{rel}: states no expectation (expect: rule=... or expect: none)")
        return

    binary = work / fixture.stem
    command = [analyzer, "-o", str(binary), "--timeout", "30"]
    completed = subprocess.run([*command, "--format=sarif", "--", *args, rel], cwd=test_dir,
                               capture_output=True, text=True, timeout=120)
    findings = sarif_findings(completed.stdout)
    if findings is None:
        fail(f"{rel}: no SARIF log on stdout\n{completed.stdout}{completed.stderr}")
        return
    verdict = 1 if findings_expected else 0
    if completed.returncode != verdict:
        fail(f"{rel}: exit {verdict} expected, got {completed.returncode}\n{completed.stderr}")

    remaining = list(findings)
    for expected in findings_expected:
        found = next((f for f in remaining if matches(expected, f, rel)), None)
        if found is None:
            fail(f"{rel}: no finding matches {describe(expected)}")
        else:
            remaining.remove(found)
    for finding in remaining:
        fail(f"{rel}: unexpected finding {describe(finding)}")

    program = [e for e in expectations if "program-exit" in e or "output" in e]
    if program:
        completed = subprocess.run([*command, "--show-output", "--", *args, rel], cwd=test_dir,
                                   capture_output=True, text=True, timeout=120)
        text = completed.stdout + completed.stderr
        for expected in program:
            if "program-exit" in expected:
                wanted = f"runtime-analyzer: exit_code={expected['program-exit']}"
                if wanted not in completed.stdout:
                    fail(f"{rel}: program exit {expected['program-exit']} expected\n{text}")
            if "output" in expected and expected["output"] not in text:
                fail(f"{rel}: program output lacks {expected['output']!r}\n{text}")


def main() -> int:
    analyzer = str(Path(sys.argv[1]).resolve())
    test_dir = Path(sys.argv[2]).resolve()
    work = Path(sys.argv[3]).resolve()
    work.mkdir(parents=True, exist_ok=True)
    fixtures = sorted(p for p in test_dir.rglob("*") if p.suffix in SOURCE_SUFFIXES)
    if not fixtures:
        fail(f"no fixture under {test_dir}")
    for fixture in fixtures:
        before = failures
        check(analyzer, test_dir, work, fixture)
        if failures == before:
            print(f"[PASS] {fixture.relative_to(test_dir).as_posix()}")
    if failures:
        print(f"{failures} fixture check(s) failed", file=sys.stderr)
        return 1
    print(f"check_fixtures: {len(fixtures)} fixtures proved what they state")
    return 0


if __name__ == "__main__":
    sys.exit(main())
