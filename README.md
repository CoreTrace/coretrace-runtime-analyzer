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
runtime-analyzer --timeout 10 -- main.c
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
| `vtable-null-this` | CWE-476 | virtual call site |
| `vtable-use-after-free` | CWE-416 | virtual call site |
| `vtable-corrupted` | CWE-843 | virtual call site |
| `vcall-invalid-target` | CWE-843 | virtual call site |
| `vtable-type-mismatch` | CWE-843, warning | virtual call site |

The vtable rules come from the `vtable` module's diagnostics (`--ct-modules=alloc,vtable
--ct-vtable-diag`): each box the runtime logs at `WARN` level is one finding, its message listing
the box's warnings, and its rule the most specific warning. Boxes logged at `INFO` level are
tracing and produce no finding.

Sites carry the path the source was compiled from, so run the analyzer from the directory the
static analyzers report paths from. Stack objects are checked by the `bounds` module, which the
default module set enables.

`--format sarif` prints a SARIF 2.1.0 log instead of the text summary: one result per finding,
with the faulting access as its location and the allocation site as related location `0`. In
`--test-dir` mode, the log holds the findings of every program in one run.

## Timeout

Each run is bounded by `--timeout <seconds>` (60 by default, `0` disables the limit). The program
starts in its own process group with its stdin on `/dev/null`, so a program waiting for input ends
at EOF. When the deadline passes, the whole group is killed, the output captured so far is still
parsed for findings, the summary reports `timed_out=1`, and the diagnostics say
`program timed out after N s`. Library callers set `AnalyzerOptions::timeout` and read
`AnalyzerResult::timed_out`.

## Exit Status

The exit status is the analyzer's verdict. The program's own status is reported as `exit_code=`.

| Status | Meaning |
|---|---|
| `0` | the program was built and ran, and reported no finding |
| `1` | at least one finding was reported |
| `2` | the program could not be built or run, timed out without findings, or the arguments are invalid |

In batch mode the status is the worst of all the tests, and `--strict-test-exit` raises it to at
least `1` when a program exits non-zero.

## Batch Test Directory Mode

Use `--test-dir <path>` to run every `.c`, `.cc`, `.cpp`, and `.cxx` source under a test directory.
Each source is compiled and executed as a separate instrumented binary, which avoids linker
collisions between test files that each define `main`.

Arguments after `--` are shared compiler/CoreTrace flags for every test file. Batch mode keeps going
after runtime failures and timeouts, marks them `[RUNTIME]` and `[TIMEOUT]` in the per-test lines,
and counts them in the batch summary. Add `--strict-test-exit` if a non-zero test binary exit
should make the analyzer return a non-zero exit code.

## Tests

The suite is registered with CTest by the top-level project only, so FetchContent consumers do not
inherit it. The end-to-end checks need Python 3 at test time.

```zsh
cmake -S . -B build -DLLVM_DIR=$(brew --prefix llvm@20)/lib/cmake/llvm
cmake --build build
ctest --test-dir build --output-on-failure
```

| Test | Checks |
|---|---|
| `findings_unit`, `process_unit` | the report parser and the process runner (`unittests/`) |
| `findings` | one fixture per finding kind (`test/findings/`) and the vtable fixtures: rule, CWE, location, exit status, SARIF and text output, batch mode |
| `timeout` | hung, stdin-reading and forking programs, alone and in a batch |
| `compile_failure` | a source that fails code generation fails its own analysis only |
| `hello_runs` | `test/examples/fixtures/hello.c` runs and its entry/exit events are collected |
| `sweep_compiles` | every source under `test/` compiles (`--test-dir test --no-run`) |
| `sweep_runs` | every binary runs without a timeout (`--test-dir test --timeout 10 -- --ct-modules=alloc`) |
