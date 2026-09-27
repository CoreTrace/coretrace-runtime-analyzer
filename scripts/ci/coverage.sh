#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# coverage.sh <build directory> <output directory> [<line coverage floor, in percent>]
#
# Measures how much of this project's own code (src/, include/, main.cpp) the test suite runs,
# from a build configured with -DCORETRACE_COVERAGE=ON. Writes the llvm-cov text report and an
# HTML report, prints the totals, adds them to the GitHub Actions job summary when there is
# one, and fails when the line coverage is below the floor. A failing test fails the script.
#
# LLVM_PROFDATA and LLVM_COV name the LLVM tools matching the compiler (llvm-profdata-20 and
# llvm-cov-20 for clang-20); by default llvm-profdata and llvm-cov, through xcrun on macOS.
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "usage: $0 <build directory> <output directory> [<line coverage floor>]" >&2
    exit 2
fi
build=$(cd "$1" && pwd)
mkdir -p "$2"
out=$(cd "$2" && pwd)
floor=${3:-0}
source_dir=$(cd "$(dirname "$0")/../.." && pwd)

tool_prefix=
if [ "$(uname -s)" = Darwin ]; then
    tool_prefix="xcrun "
fi
profdata=${LLVM_PROFDATA:-${tool_prefix}llvm-profdata}
cov=${LLVM_COV:-${tool_prefix}llvm-cov}

# The CLI and every unit test executable: each holds part of the code the tests ran.
objects=
for binary in "$build"/*_test; do
    if [ -x "$binary" ]; then
        objects="$objects -object $binary"
    fi
done

rm -rf "$out/profiles" "$out/html"
mkdir -p "$out/profiles"
# %4m: one profile per binary, merged by the processes that share it; the Python tests spawn
# the CLI many times.
LLVM_PROFILE_FILE="$out/profiles/%4m.profraw" ctest --test-dir "$build" --output-on-failure

$profdata merge -sparse "$out"/profiles/*.profraw -o "$out/all.profdata"
sources="$source_dir/src $source_dir/include $source_dir/main.cpp"
# llvm-cov warns that functions "have mismatched data": an inline function that one binary
# uses and another does not emit has two records. Each binary's counts are still read from its
# own record, so the totals are right.
# shellcheck disable=SC2086 # $objects and $sources are lists of words.
$cov report "$build/runtime-analyzer" $objects -instr-profile "$out/all.profdata" $sources \
    > "$out/report.txt"
# shellcheck disable=SC2086
$cov show "$build/runtime-analyzer" $objects -instr-profile "$out/all.profdata" -format=html \
    -output-dir "$out/html" $sources

# The TOTAL row of `llvm-cov report`: regions, missed, cover, functions, missed, executed,
# lines, missed, cover, branches, missed, cover.
lines=$(awk '$1 == "TOTAL" { print $10 }' "$out/report.txt")
{
    echo "| Lines | Functions | Branches |"
    echo "|---|---|---|"
    awk '$1 == "TOTAL" { printf "| %s | %s | %s |\n", $10, $7, $13 }' "$out/report.txt"
} > "$out/summary.md"
grep -v '^-' "$out/report.txt"
cat "$out/summary.md"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    {
        echo "### Coverage of src/, include/ and main.cpp (floor: ${floor}% of lines)"
        echo
        cat "$out/summary.md"
    } >> "$GITHUB_STEP_SUMMARY"
fi

if awk -v lines="${lines%\%}" -v floor="$floor" 'BEGIN { exit !(lines + 0 < floor + 0) }'; then
    echo "coverage: ${lines} of lines is below the floor of ${floor}%" >&2
    exit 1
fi
echo "coverage: ${lines} of lines, floor ${floor}%"
