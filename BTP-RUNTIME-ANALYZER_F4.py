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
RUNTIME_EXIT_RE = re.compile(r"^runtime-analyzer:\s+exit_code=(?P<value>-?\d+)$")
ANSI_GREEN = "\033[32m"
ANSI_PURPLE = "\033[35m"
ANSI_RED = "\033[31m"
ANSI_RESET = "\033[0m"
SEPARATOR = "--------"
F4_MARKER = "coretrace-runtime-analyzer-f4"
F4_SOURCE = f"""\
#include <stdio.h>

static int f4_helper(int value)
{{
    return value + 1;
}}

int main(void)
{{
    puts("{F4_MARKER}");
    return f4_helper(40) == 41 ? 0 : 1;
}}
"""


@dataclass(frozen=True)
class ProbeSource:
    path: Path
    mode: str


@dataclass
class F4Result:
    use_color: bool
    source_name: str
    failures: int = 0

    def fail(self, message: str) -> None:
        self.failures += 1
        print(f"[F4] {self.file_label()} {message}={status_label(False, self.use_color)}")

    def ok(self, message: str) -> None:
        print(f"[F4] {self.file_label()} {message}={status_label(True, self.use_color)}")

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
    print(f"[F4] file={colorize(path.name, ANSI_PURPLE, use_color)}")
    print_separator()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Prove minimal execution of an instrumented binary and basic "
            "collection through coretrace-runtime-analyzer."
        )
    )
    parser.add_argument(
        "--runtime-analyzer",
        default="build/runtime-analyzer",
        help="Path to the runtime-analyzer executable. Default: build/runtime-analyzer",
    )
    parser.add_argument(
        "--source",
        help=(
            "Explicit C/C++ source to compile instead of the generated F4 probe. "
            "When omitted, a minimal proof source is generated."
        ),
    )
    parser.add_argument(
        "--expected-output",
        help=(
            "Output marker expected in the instrumented program output. "
            "Defaults to the generated F4 marker only when --source is omitted."
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="runtime-analyzer-artifacts/btp-runtime-analyzer-f4",
        help="Directory where generated F4 artifacts are written.",
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


def parse_runtime_exit_code(output: str) -> int | None:
    for line in output.splitlines():
        match = RUNTIME_EXIT_RE.match(line)
        if match:
            return int(match.group("value"))
    return None


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
        print(f"[F4] build_timeout={status_label(False, use_color)}")
        return False

    if completed.stdout:
        print_stream("build stdout", completed.stdout)
    if completed.stderr:
        print_stream("build stderr", completed.stderr)
    return completed.returncode == 0


def select_probe_source(root: Path, args: argparse.Namespace, output_dir: Path) -> ProbeSource:
    if args.source:
        return ProbeSource(resolve_under_repo(root, args.source), "explicit")

    probe_dir = output_dir / "proof"
    probe_dir.mkdir(parents=True, exist_ok=True)
    probe_source = probe_dir / "minimal_execution_probe.c"
    probe_source.write_text(F4_SOURCE, encoding="utf-8")
    return ProbeSource(probe_source.resolve(), "generated")


def expected_output_for(args: argparse.Namespace, probe: ProbeSource) -> str | None:
    if args.expected_output is not None:
        return args.expected_output
    if probe.mode == "generated":
        return F4_MARKER
    return None


def run_f4_proof(
    root: Path,
    runtime_analyzer: Path,
    probe: ProbeSource,
    output_dir: Path,
    timeout: float,
    expected_output: str | None,
    use_color: bool,
) -> int:
    result = F4Result(use_color=use_color, source_name=probe.path.name)
    binary = output_dir / f"{probe.path.stem}.instrumented"
    command = [
        str(runtime_analyzer),
        "-o",
        str(binary),
        "--show-events",
        "--show-output",
        "--",
        str(probe.path),
    ]

    print_file_header(probe.path, use_color)
    print(f"[F4] source_mode={probe.mode}")
    print(f"[F4] binary={binary}")
    print_separator()
    completed = run_command(command, root, timeout=timeout)
    print_separator()

    if isinstance(completed, subprocess.TimeoutExpired):
        print_stream("runtime-analyzer stdout", completed.stdout)
        print_stream("runtime-analyzer stderr", completed.stderr)
        result.fail("runtime_analyzer_timeout")
        result.fail("runtime_analyzer_exit_zero")
        result.fail("instrumented_binary_generated")
        result.fail("instrumented_binary_executable")
        return result.failures

    print_stream("runtime-analyzer stdout", completed.stdout)
    print_stream("runtime-analyzer stderr", completed.stderr)
    print_separator()

    combined_output = f"{completed.stdout}\n{completed.stderr}"
    collection = parse_collection_summary(completed.stdout)
    runtime_exit_code = parse_runtime_exit_code(completed.stdout)

    if completed.returncode == 0:
        result.ok("runtime_analyzer_exit_zero")
    else:
        result.fail("runtime_analyzer_exit_zero")

    if binary.is_file():
        result.ok("instrumented_binary_generated")
    else:
        result.fail("instrumented_binary_generated")

    if binary.is_file() and os.access(binary, os.X_OK):
        result.ok("instrumented_binary_executable")
    else:
        result.fail("instrumented_binary_executable")

    if runtime_exit_code == 0:
        result.ok("instrumented_program_exit_zero")
    else:
        result.fail("instrumented_program_exit_zero")

    if expected_output is None:
        print(f"[F4] {result.file_label()} program_output_check=skipped")
    elif expected_output in combined_output:
        result.ok("program_output_captured")
    else:
        result.fail("program_output_captured")

    print_separator()
    print("--- collection summary ---")
    for key in (
        "coretrace_lines",
        "entry_events",
        "exit_events",
        "allocation_events",
        "bounds_errors",
        "leak_reports",
        "vtable_events",
        "warnings",
        "errors",
    ):
        print(f"{key}={collection.get(key, 0)}")
    print_separator()

    if collection.get("coretrace_lines", 0) > 0:
        result.ok("coretrace_lines_collected")
    else:
        result.fail("coretrace_lines_collected")

    if collection.get("entry_events", 0) > 0:
        result.ok("entry_events_collected")
    else:
        result.fail("entry_events_collected")

    if collection.get("exit_events", 0) > 0:
        result.ok("exit_events_collected")
    else:
        result.fail("exit_events_collected")

    return result.failures


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    root = repo_root()
    use_color = should_use_color(args.no_color)
    output_dir = resolve_under_repo(root, args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    runtime_analyzer = resolve_under_repo(root, args.runtime_analyzer)

    if args.build_first and not build_runtime_analyzer(root, use_color):
        return 1

    probe = select_probe_source(root, args, output_dir)
    expected_output = expected_output_for(args, probe)
    failures = run_f4_proof(
        root=root,
        runtime_analyzer=runtime_analyzer,
        probe=probe,
        output_dir=output_dir,
        timeout=args.timeout,
        expected_output=expected_output,
        use_color=use_color,
    )

    print_separator()
    if failures == 0:
        print(f"[F4] result={status_label(True, use_color)}")
        return 0

    print(f"[F4] result={status_label(False, use_color)} failures={failures}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
