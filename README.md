# coretrace-runtime-analyzer

Minimal execution and collection tool for CoreTrace-instrumented binaries.

`runtime-analyzer` uses `coretrace-compiler` in library mode, builds an instrumented binary from
forwarded compiler arguments, executes it, captures stdout/stderr, and prints a small runtime event
summary.

## Usage

```zsh
runtime-analyzer -o ./app -- --ct-modules=trace,alloc,bounds main.c
runtime-analyzer --show-events -- main.c
runtime-analyzer --run-arg input.txt --env CT_LOG_LEVEL=info -- main.c
runtime-analyzer --test-dir test --output-dir /tmp/runtime-analyzer-tests -- --ct-modules=all
runtime-analyzer --format sarif -- --ct-modules=alloc,bounds main.c
```

Arguments before `--` belong to `runtime-analyzer`. Arguments after `--` are forwarded to
`coretrace-compiler` and then to Clang. The analyzer enables instrumentation through the
`compilerlib::compile(..., instrument=true)` API, so `--instrument` is optional and ignored if it is
present after `--`.

The initial collection is intentionally basic: it counts CoreTrace log lines, function entry/exit
events, allocation events, bounds errors, leak reports, vtable diagnostics, warnings, and errors.

## Findings

Each error the CoreTrace runtime reports while the program runs becomes a finding, available as
`AnalyzerResult::findings` through the library API and printed after the summary:

```text
runtime-analyzer: findings=1
  findings/heap_overflow_write.c:7:15: error: heap-buffer-overflow WRITE of size 4 [heap-buffer-overflow, CWE-122]
    findings/heap_overflow_write.c:6:19: note: allocated here
```

| Rule | CWE | Locations |
|---|---|---|
| `heap-buffer-overflow` | CWE-122 (write), CWE-125 (read) | faulting access, allocation site |
| `stack-buffer-overflow` | CWE-121 (write), CWE-125 (read) | faulting access, the object's function |
| `heap-use-after-free` | CWE-416 | faulting access, allocation site |
| `double-free` | CWE-415 | second free, allocation site |
| `memory-leak` | CWE-401, warning | allocation site |

Sites carry the path the source was compiled from, so run the analyzer from the directory the
static analyzers report paths from. Stack objects are checked by the `bounds` module, which the
default module set enables.

`--format sarif` prints a SARIF 2.1.0 log instead of the text summary: one result per finding,
with the faulting access as its location and the allocation site as related location `0`. In
`--test-dir` mode, the log holds the findings of every program in one run.

## Exit Status

The exit status is the analyzer's verdict. The program's own status is reported as `exit_code=`.

| Status | Meaning |
|---|---|
| `0` | the program was built and ran, and reported no finding |
| `1` | at least one finding was reported |
| `2` | the program could not be built or run, or the arguments are invalid |

In batch mode the status is the worst of all the tests, and `--strict-test-exit` raises it to at
least `1` when a program exits non-zero.

## Batch Test Directory Mode

Use `--test-dir <path>` to run every `.c`, `.cc`, `.cpp`, and `.cxx` source under a test directory.
Each source is compiled and executed as a separate instrumented binary, which avoids linker
collisions between test files that each define `main`.

Arguments after `--` are shared compiler/CoreTrace flags for every test file. Batch mode keeps going
after runtime failures and reports them at the end. Add `--strict-test-exit` if a non-zero test
binary exit should make the analyzer return a non-zero exit code.

## Python Test Runner

`BTP-RUNTIME-ANALYZER.py` compiles every C/C++ source in `test/`, verifies that each source has a
generated executable, then runs every binary with a 10 second timeout and prints stdout/stderr.
Before the directory sweep, it also runs a generated minimal C probe and asserts that
`runtime-analyzer` builds an instrumented binary, executes it, captures the program output, and
collects basic CoreTrace entry/exit lines.

```zsh
python3 BTP-RUNTIME-ANALYZER.py
python3 BTP-RUNTIME-ANALYZER.py --timeout 10 -- --ct-no-alloc-trace --ct-no-trace --ct-bounds-no-abort
```

Non-zero binary exits are reported without failing the script by default, because some runtime tests
intentionally abort. Use `--strict-exit` to fail on any non-zero binary exit.

## F4 Minimal Runtime Analyzer Proof

`BTP-RUNTIME-ANALYZER_F4.py` proves minimal execution of an instrumented binary and basic runtime
collection through `coretrace-runtime-analyzer`. It generates a small C probe in
`runtime-analyzer-artifacts/`, compiles it with `runtime-analyzer`, verifies that the instrumented
binary exists and is executable, then checks that the program output and CoreTrace entry/exit
collection were captured.

```zsh
python3 BTP-RUNTIME-ANALYZER_F4.py
python3 BTP-RUNTIME-ANALYZER_F4.py --build-first
```
