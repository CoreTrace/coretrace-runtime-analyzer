#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import argparse
import os
import re
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence


SOURCE_EXTENSIONS = {".c", ".cc", ".cpp", ".cxx"}
BATCH_RECORD_RE = re.compile(
    r"^runtime-analyzer: \[(?P<status>[A-Z]+)\] "
    r"(?P<source>.*?) exit_code=(?P<exit_code>-?\d+) "
    r"coretrace_lines=(?P<coretrace_lines>\d+) binary=(?P<binary>.*)$"
)
COLLECTION_RECORD_RE = re.compile(r"^\s*(?P<name>[a-z_]+)=(?P<value>\d+)$")
PROOF_MARKER = "coretrace-runtime-analyzer-proof"
PROOF_SOURCE = f"""\
#include <stdio.h>

static int proof_helper(int value) {{
    return value + 1;
}}

int main(void) {{
    puts("{PROOF_MARKER}");
    return proof_helper(40) == 41 ? 0 : 1;
}}
"""


@dataclass(frozen=True)
class CompiledBinary:
    source: Path
    binary: Path
    status: str
    exit_code: int
    coretrace_lines: int


@dataclass
class ScriptResult:
    proof_failures: int = 0
    compile_failures: int = 0
    missing_binaries: int = 0
    non_executable_binaries: int = 0
    timeouts: int = 0
    nonzero_exits: int = 0

    def failed(self, strict_exit: bool) -> bool:
        return (
            self.proof_failures > 0
            or self.compile_failures > 0
            or self.missing_binaries > 0
            or self.non_executable_binaries > 0
            or self.timeouts > 0
            or (strict_exit and self.nonzero_exits > 0)
        )


def split_compiler_args(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    if "--" not in argv:
        return list(argv), []
    index = argv.index("--")
    return list(argv[:index]), list(argv[index + 1 :])


def parse_args(argv: Sequence[str]) -> tuple[argparse.Namespace, list[str]]:
    analyzer_args, compiler_args = split_compiler_args(argv)
    parser = argparse.ArgumentParser(
        description=(
            "Compile every C/C++ source in TEST with runtime-analyzer, verify the "
            "generated binaries, and execute each binary with a timeout."
        )
    )
    parser.add_argument(
        "--test-dir",
        default="test",
        help="Directory containing test files. Default: test",
    )
    parser.add_argument(
        "--runtime-analyzer",
        default="build/runtime-analyzer",
        help="Path to the runtime-analyzer executable. Default: build/runtime-analyzer",
    )
    parser.add_argument(
        "--output-dir",
        default="runtime-analyzer-artifacts/btp-runtime-analyzer",
        help="Directory where generated test binaries are written.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Execution timeout in seconds for each generated binary. Default: 10",
    )
    parser.add_argument(
        "--build-first",
        action="store_true",
        help="Run cmake --build build --target runtime-analyzer before testing.",
    )
    parser.add_argument(
        "--skip-proof",
        action="store_true",
        help="Skip the minimal runtime-analyzer proof case.",
    )
    parser.add_argument(
        "--strict-exit",
        action="store_true",
        help="Fail when a generated binary exits with a non-zero status.",
    )
    parser.add_argument(
        "--show-compile-output",
        action="store_true",
        help="Print runtime-analyzer compilation stdout/stderr.",
    )
    return parser.parse_args(analyzer_args), compiler_args


def repo_root() -> Path:
    return Path(__file__).resolve().parent


def resolve_under_repo(root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


def resolve_directory_case_insensitive(path: Path) -> Path:
    if path.exists():
        return path

    parent = path.parent
    if not parent.exists():
        return path

    requested = path.name.lower()
    for child in parent.iterdir():
        if child.name.lower() == requested and child.is_dir():
            return child.resolve()
    return path


def relative_to_root(root: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def discover_sources(test_dir: Path) -> list[Path]:
    return sorted(
        path.resolve()
        for path in test_dir.rglob("*")
        if path.is_file() and path.suffix in SOURCE_EXTENSIONS
    )


def discover_non_sources(test_dir: Path, sources: Iterable[Path]) -> list[Path]:
    source_set = {source.resolve() for source in sources}
    return sorted(
        path.resolve()
        for path in test_dir.rglob("*")
        if path.is_file() and path.resolve() not in source_set
    )


def print_stream(title: str, text: str | bytes | None) -> None:
    if isinstance(text, bytes):
        text = text.decode(errors="replace")
    if text is None:
        text = ""

    print(f"--- {title} ---")
    if text:
        print(text, end="" if text.endswith("\n") else "\n")
    else:
        print("<empty>")


def run_checked(command: Sequence[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    print(f"$ {shlex.join(command)}")
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def build_runtime_analyzer(root: Path) -> bool:
    completed = run_checked(
        ["cmake", "--build", "build", "--target", "runtime-analyzer"], root
    )
    if completed.stdout:
        print_stream("build stdout", completed.stdout)
    if completed.stderr:
        print_stream("build stderr", completed.stderr)
    return completed.returncode == 0


def parse_collection_summary(output: str) -> dict[str, int]:
    summary: dict[str, int] = {}
    for line in output.splitlines():
        match = COLLECTION_RECORD_RE.match(line)
        if match:
            summary[match.group("name")] = int(match.group("value"))
    return summary


def run_minimal_runtime_analyzer_proof(
    root: Path,
    runtime_analyzer: Path,
    output_dir: Path,
    timeout: float,
    result: ScriptResult,
) -> None:
    print("\n===== PROOF Minimal execution and basic collection =====")
    proof_dir = output_dir / "proof"
    proof_dir.mkdir(parents=True, exist_ok=True)
    proof_source = proof_dir / "minimal_execution_probe.c"
    proof_binary = proof_dir / "minimal_execution_probe"
    proof_source.write_text(PROOF_SOURCE, encoding="utf-8")

    command = [
        str(runtime_analyzer),
        "-o",
        str(proof_binary),
        "--show-output",
        "--",
        str(proof_source),
    ]
    print(f"$ {shlex.join(command)}")

    try:
        completed = subprocess.run(
            command,
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        result.proof_failures += 1
        print("[PROOF] FAIL: runtime-analyzer timed out")
        print_stream("proof stdout", error.stdout)
        print_stream("proof stderr", error.stderr)
        return

    print_stream("proof stdout", completed.stdout)
    print_stream("proof stderr", completed.stderr)

    collection = parse_collection_summary(completed.stdout)
    checks = {
        "runtime_analyzer_exit_zero": completed.returncode == 0,
        "binary_generated": proof_binary.is_file(),
        "binary_executable": os.access(proof_binary, os.X_OK),
        "program_output_captured": PROOF_MARKER in completed.stdout,
        "coretrace_lines_collected": collection.get("coretrace_lines", 0) > 0,
        "entry_events_collected": collection.get("entry_events", 0) > 0,
        "exit_events_collected": collection.get("exit_events", 0) > 0,
    }

    for name, passed in checks.items():
        print(f"[PROOF] {name}={'ok' if passed else 'fail'}")

    print(
        "[PROOF] collection "
        f"coretrace_lines={collection.get('coretrace_lines', 0)} "
        f"entry_events={collection.get('entry_events', 0)} "
        f"exit_events={collection.get('exit_events', 0)}"
    )

    if all(checks.values()):
        print(
            "[PROOF] PASS: Minimal execution of an instrumented binary and "
            "basic collection (WIP) via coretrace-runtime-analyzer."
        )
        return

    result.proof_failures += 1
    print(
        "[PROOF] FAIL: Minimal execution of an instrumented binary and "
        "basic collection was not proven."
    )


def parse_batch_records(root: Path, output: str) -> dict[Path, CompiledBinary]:
    records: dict[Path, CompiledBinary] = {}
    for line in output.splitlines():
        match = BATCH_RECORD_RE.match(line)
        if not match:
            continue

        source = Path(match.group("source"))
        if not source.is_absolute():
            source = root / source

        binary = Path(match.group("binary"))
        if not binary.is_absolute():
            binary = root / binary

        source = source.resolve()
        records[source] = CompiledBinary(
            source=source,
            binary=binary.resolve(),
            status=match.group("status"),
            exit_code=int(match.group("exit_code")),
            coretrace_lines=int(match.group("coretrace_lines")),
        )
    return records


def compile_sources(
    root: Path,
    runtime_analyzer: Path,
    test_dir: Path,
    output_dir: Path,
    compiler_args: Sequence[str],
    show_compile_output: bool,
) -> tuple[int, dict[Path, CompiledBinary]]:
    output_dir.mkdir(parents=True, exist_ok=True)
    command = [
        str(runtime_analyzer),
        "--test-dir",
        str(test_dir),
        "--output-dir",
        str(output_dir),
        "--no-run",
        "--",
        *compiler_args,
    ]
    completed = run_checked(command, root)

    if show_compile_output or completed.returncode != 0:
        print_stream("compile stdout", completed.stdout)
        print_stream("compile stderr", completed.stderr)

    records = parse_batch_records(root, completed.stdout)
    return completed.returncode, records


def verify_binaries(
    root: Path,
    sources: Sequence[Path],
    records: dict[Path, CompiledBinary],
    result: ScriptResult,
) -> list[CompiledBinary]:
    verified: list[CompiledBinary] = []
    for source in sources:
        record = records.get(source)
        if record is None:
            print(f"[COMPILE] {relative_to_root(root, source)}: no batch record emitted")
            result.compile_failures += 1
            continue

        if record.status != "PASS":
            print(
                f"[COMPILE] {relative_to_root(root, source)}: "
                f"runtime-analyzer status={record.status}"
            )
            result.compile_failures += 1
            continue

        if not record.binary.is_file():
            print(
                f"[MISSING] {relative_to_root(root, source)}: "
                f"binary not found at {record.binary}"
            )
            result.missing_binaries += 1
            continue

        if not os.access(record.binary, os.X_OK):
            print(
                f"[NOT-EXECUTABLE] {relative_to_root(root, source)}: "
                f"binary is not executable at {record.binary}"
            )
            result.non_executable_binaries += 1
            continue

        print(
            f"[BINARY] {relative_to_root(root, source)} -> "
            f"{relative_to_root(root, record.binary)}"
        )
        verified.append(record)

    return verified


def execute_binary(
    root: Path, record: CompiledBinary, timeout: float, result: ScriptResult
) -> None:
    label = relative_to_root(root, record.source)
    print(f"\n===== EXEC {label} =====")
    print(f"binary: {record.binary}")
    print(f"timeout: {timeout:g}s")

    try:
        completed = subprocess.run(
            [str(record.binary)],
            cwd=root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        result.timeouts += 1
        print("[TIMEOUT]")
        print_stream("stdout", error.stdout)
        print_stream("stderr", error.stderr)
        return

    print(f"exit_code: {completed.returncode}")
    if completed.returncode != 0:
        result.nonzero_exits += 1
    print_stream("stdout", completed.stdout)
    print_stream("stderr", completed.stderr)


def main(argv: Sequence[str]) -> int:
    args, compiler_args = parse_args(argv)
    root = repo_root()
    test_dir = resolve_directory_case_insensitive(
        resolve_under_repo(root, args.test_dir)
    )
    runtime_analyzer = resolve_under_repo(root, args.runtime_analyzer)
    output_dir = resolve_under_repo(root, args.output_dir)

    if args.build_first and not build_runtime_analyzer(root):
        return 1

    if not test_dir.is_dir():
        print(f"error: test directory not found: {test_dir}", file=sys.stderr)
        return 1
    if not runtime_analyzer.is_file():
        print(
            f"error: runtime-analyzer not found: {runtime_analyzer}\n"
            "run `cmake --build build --target runtime-analyzer` or pass "
            "--runtime-analyzer <path>",
            file=sys.stderr,
        )
        return 1

    sources = discover_sources(test_dir)
    skipped = discover_non_sources(test_dir, sources)
    print(f"test_dir: {test_dir}")
    print(f"runtime_analyzer: {runtime_analyzer}")
    print(f"output_dir: {output_dir}")
    print(f"source_files: {len(sources)}")
    print(f"non_source_files_skipped: {len(skipped)}")

    if not sources:
        print("error: no C/C++ source files found", file=sys.stderr)
        return 1

    result = ScriptResult()
    if not args.skip_proof:
        run_minimal_runtime_analyzer_proof(
            root, runtime_analyzer, output_dir, args.timeout, result
        )

    compile_exit, records = compile_sources(
        root,
        runtime_analyzer,
        test_dir,
        output_dir,
        compiler_args,
        args.show_compile_output,
    )
    if compile_exit != 0:
        result.compile_failures += 1

    verified = verify_binaries(root, sources, records, result)
    for record in verified:
        execute_binary(root, record, args.timeout, result)

    print("\n===== SUMMARY =====")
    print(f"proof_failures={result.proof_failures}")
    print(f"sources={len(sources)}")
    print(f"binaries_verified={len(verified)}")
    print(f"compile_failures={result.compile_failures}")
    print(f"missing_binaries={result.missing_binaries}")
    print(f"non_executable_binaries={result.non_executable_binaries}")
    print(f"timeouts={result.timeouts}")
    print(f"nonzero_exits={result.nonzero_exits}")
    print(f"strict_exit={str(args.strict_exit).lower()}")

    return 1 if result.failed(args.strict_exit) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
