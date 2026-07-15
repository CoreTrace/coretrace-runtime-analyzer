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
from typing import Sequence


COLLECTION_RECORD_RE = re.compile(r"^\s*(?P<name>[a-z_]+)=(?P<value>\d+)$")
ANSI_GREEN = "\033[32m"
ANSI_PURPLE = "\033[35m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"
SEPARATOR = "--------"
F11_BEFORE_MARKER = "coretrace-runtime-analyzer-f11-before-overflow"
F11_AFTER_MARKER = "coretrace-runtime-analyzer-f11-after-overflow"
F11_SOURCE = f"""\
#include <stdio.h>
#include <stdlib.h>

int main(void)
{{
    volatile unsigned char* buffer = (volatile unsigned char*)malloc(8);
    if (buffer == NULL)
    {{
        return 2;
    }}

    for (unsigned long i = 0; i < 8; ++i)
    {{
        buffer[i] = (unsigned char)i;
    }}

    puts("{F11_BEFORE_MARKER}");
    buffer[8] = 0xF1;
    puts("{F11_AFTER_MARKER}");

    free((void*)buffer);
    return 0;
}}
"""


@dataclass(frozen=True)
class ProbeSource:
    path: Path
    mode: str


@dataclass
class F11Result:
    use_color: bool
    source_name: str
    failures: int = 0

    def fail(self, message: str) -> None:
        self.failures += 1
        print(f"[F11] {self.file_label()} {message}={status_label(False, self.use_color)}")

    def ok(self, message: str) -> None:
        print(f"[F11] {self.file_label()} {message}={status_label(True, self.use_color)}")

    def file_label(self) -> str:
        return colorize(self.source_name, ANSI_PURPLE, self.use_color)


def colorize(text: str, color: str, enabled: bool) -> str:
    if not enabled:
        return text
    return f"{color}{text}{ANSI_RESET}"


def status_label(passed: bool, use_color: bool) -> str:
    if passed:
        return colorize("OK", ANSI_GREEN, use_color)
    return colorize("NO", ANSI_RED, use_color)


def should_use_color(disabled: bool) -> bool:
    return not disabled


def print_separator() -> None:
    print(SEPARATOR)


def print_file_header(path: Path, use_color: bool) -> None:
    print_separator()
    print(f"[F11] file={colorize(path.name, ANSI_PURPLE, use_color)}")
    print_separator()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prove overflow detection at runtime via bounds instrumentation "
            "through coretrace-runtime-analyzer."
        )
    )
    parser.add_argument(
        "--runtime-analyzer",
        default="build/runtime-analyzer",
        help="Path to the runtime-analyzer executable. Default: build/runtime-analyzer",
    )
    parser.add_argument(
        "--test-dir",
        default="test",
        help="Directory searched for an existing ct_bounds_overflow fixture.",
    )
    parser.add_argument(
        "--source",
        help="Explicit C/C++ overflow probe source to compile instead of auto-selection.",
    )
    parser.add_argument(
        "--output-dir",
        default="runtime-analyzer-artifacts/btp-runtime-analyzer-f11",
        help="Directory where generated F11 artifacts are written.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Execution timeout in seconds for runtime-analyzer. Default: 10",
    )
    parser.add_argument(
        "--build-first",
        action="store_true",
        help="Run cmake --build build --target runtime-analyzer before testing.",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored OK/NO status output.",
    )
    return parser.parse_args(argv)


def repo_root() -> Path:
    return Path(__file__).resolve().parent


def resolve_under_repo(root: Path, value: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        path = root / path
    return path.resolve()


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


def parse_collection_summary(output: str) -> dict[str, int]:
    summary: dict[str, int] = {}
    for line in output.splitlines():
        match = COLLECTION_RECORD_RE.match(line)
        if match:
            summary[match.group("name")] = int(match.group("value"))
    return summary


def run_command(
    command: Sequence[str], cwd: Path, timeout: float | None = None
) -> subprocess.CompletedProcess[str] | subprocess.TimeoutExpired[str]:
    print(f"$ {shlex.join(command)}")
    try:
        return subprocess.run(
            command,
            cwd=cwd,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        return error


def build_runtime_analyzer(root: Path, use_color: bool) -> bool:
    completed = run_command(
        ["cmake", "--build", "build", "--target", "runtime-analyzer"], root
    )
    if isinstance(completed, subprocess.TimeoutExpired):
        print(f"[F11] build_timeout={status_label(False, use_color)}")
        return False

    if completed.stdout:
        print_stream("build stdout", completed.stdout)
    if completed.stderr:
        print_stream("build stderr", completed.stderr)
    return completed.returncode == 0


def find_existing_bounds_fixture(test_dir: Path) -> Path | None:
    candidates = [
        test_dir / "ct_bounds_overflow.c",
        test_dir / "ct_bounds_overflow.cpp",
        test_dir / "ct_bounds_heap_overflow.c",
        test_dir / "ct_bounds_heap_overflow.cpp",
        test_dir / "ct_heap_buffer_overflow.c",
        test_dir / "ct_heap_buffer_overflow.cpp",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def select_probe_source(root: Path, args: argparse.Namespace, output_dir: Path) -> ProbeSource:
    if args.source:
        return ProbeSource(resolve_under_repo(root, args.source), "explicit")

    test_dir = resolve_under_repo(root, args.test_dir)
    existing = find_existing_bounds_fixture(test_dir)
    if existing is not None:
        return ProbeSource(existing, "existing-test")

    probe_dir = output_dir / "proof"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_source = probe_dir / "ct_bounds_overflow_probe.c"
    probe_source.write_text(F11_SOURCE, encoding="utf-8")
    return ProbeSource(probe_source.resolve(), "generated")


def run_f11_proof(
    root: Path,
    runtime_analyzer: Path,
    probe: ProbeSource,
    output_dir: Path,
    timeout: float,
    use_color: bool,
) -> int:
    result = F11Result(use_color=use_color, source_name=probe.path.name)
    binary = output_dir / "ct_bounds_overflow_probe"
    command = [
        str(runtime_analyzer),
        "-o",
        str(binary),
        "--show-events",
        "--show-output",
        "--",
        "--ct-bounds",
        "--ct-bounds-no-abort",
        str(probe.path),
    ]

    print_file_header(probe.path, use_color)
    print("===== F11 Overflow detection via bounds instrumentation =====")
    print(f"probe_source: {probe.path}")
    print(f"probe_source_mode: {probe.mode}")
    print(f"output_binary: {binary}")
    print(f"timeout: {timeout:g}s")
    print_separator()

    completed = run_command(command, root, timeout)
    if isinstance(completed, subprocess.TimeoutExpired):
        result.fail("runtime_analyzer_timeout")
        print_stream("runtime-analyzer stdout", completed.stdout)
        print_stream("runtime-analyzer stderr", completed.stderr)
        return 1

    print_stream("runtime-analyzer stdout", completed.stdout)
    print_stream("runtime-analyzer stderr", completed.stderr)
    print_separator()

    combined_output = completed.stdout + completed.stderr
    collection = parse_collection_summary(completed.stdout)

    checks = {
        "runtime_analyzer_exit_zero": completed.returncode == 0,
        "binary_generated": binary.is_file(),
        "binary_executable": os.access(binary, os.X_OK),
        "program_reached_overflow_site": F11_BEFORE_MARKER in combined_output,
        "program_continued_after_detection": F11_AFTER_MARKER in combined_output,
        "heap_buffer_overflow_reported": "heap-buffer-overflow" in combined_output,
        "write_overflow_reported": "WRITE" in combined_output,
        "bounds_errors_collected": collection.get("bounds_errors", 0) > 0,
        "coretrace_lines_collected": collection.get("coretrace_lines", 0) > 0,
    }

    for name, passed in checks.items():
        if passed:
            result.ok(name)
        else:
            result.fail(name)
    print_separator()

    print(
        f"[F11] {result.file_label()} collection "
        f"coretrace_lines={collection.get('coretrace_lines', 0)} "
        f"bounds_errors={collection.get('bounds_errors', 0)} "
        f"errors={collection.get('errors', 0)}"
    )

    if result.failures == 0:
        print(
            "[F11] PASS: Overflow detection at runtime via bounds "
            "instrumentation via coretrace-runtime-analyzer."
        )
        return 0

    print(
        "[F11] FAIL: Overflow detection at runtime via bounds instrumentation "
        "was not proven."
    )
    return 1


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    root = repo_root()
    runtime_analyzer = resolve_under_repo(root, args.runtime_analyzer)
    output_dir = resolve_under_repo(root, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    use_color = should_use_color(args.no_color)

    if args.build_first and not build_runtime_analyzer(root, use_color):
        return 1

    if not runtime_analyzer.is_file():
        print(
            f"error: runtime-analyzer not found: {runtime_analyzer}\n"
            "run `cmake --build build --target runtime-analyzer` or pass "
            "--runtime-analyzer <path>",
            file=sys.stderr,
        )
        return 1

    probe = select_probe_source(root, args, output_dir)
    if not probe.path.is_file():
        print(f"error: overflow probe source not found: {probe.path}", file=sys.stderr)
        return 1

    return run_f11_proof(root, runtime_analyzer, probe, output_dir, args.timeout, use_color)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
