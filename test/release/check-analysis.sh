#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Checks that an installation laid out as a release archive analyzes a C program without an
# installed clang or LLVM: the CLI runs with an empty environment and a PATH holding only the
# system's linker, so it must compile the program with the Clang headers shipped next to it,
# link it against the runtime archives shipped next to it, run it, and report its heap overflow.
# Only a C++ build environment (g++ or gcc-c++: linker, C library and libstdc++ development
# files) comes from the system, as for building any C++ program.
#
# Usage: check-analysis.sh <prefix> <scratch dir>
set -eu

prefix=$1
work=$2
here=$(cd "$(dirname "$0")" && pwd)

rm -rf "$work"
mkdir -p "$work"
cp "$here/../findings/heap_overflow_write.c" "$work/heap_overflow_write.c"

set +e
output=$(cd "$work" && env -i PATH=/usr/bin:/bin "$prefix/bin/runtime-analyzer" \
    -o heap_overflow_write -- --ct-modules=alloc,bounds heap_overflow_write.c 2>&1)
status=$?
set -e
printf '%s\n' "$output"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}
[ "$status" -eq 1 ] || fail "expected exit status 1 (findings), got $status"
printf '%s\n' "$output" | grep -q 'heap_overflow_write.c:7:15: error: heap-buffer-overflow WRITE of size 4' ||
    fail "the heap overflow of heap_overflow_write.c is not reported"
echo "PASS: runtime-analyzer analyzes C from $prefix without an installed clang"
