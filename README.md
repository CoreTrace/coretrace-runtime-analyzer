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
```

Arguments before `--` belong to `runtime-analyzer`. Arguments after `--` are forwarded to
`coretrace-compiler` and then to Clang. The analyzer enables instrumentation through the
`compilerlib::compile(..., instrument=true)` API, so `--instrument` is optional and ignored if it is
present after `--`.

The initial collection is intentionally basic: it counts CoreTrace log lines, function entry/exit
events, allocation events, bounds errors, leak reports, vtable diagnostics, warnings, and errors.

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

## F11 Bounds Overflow Proof

`BTP-RUNTIME-ANALYZER_F11.py` proves runtime overflow detection through CoreTrace bounds
instrumentation. It uses an existing `ct_bounds_overflow` fixture if one is present in `test/`;
otherwise it generates a small heap-overflow probe in `runtime-analyzer-artifacts/`.

```zsh
python3 BTP-RUNTIME-ANALYZER_F11.py
python3 BTP-RUNTIME-ANALYZER_F11.py --no-color
```

The proof expects a generated instrumented binary, a runtime `heap-buffer-overflow` report, and a
non-zero `bounds_errors` collection count. Status checks print the tested file name in purple,
green `OK` for validated conditions, red `NO` for missing conditions, and separate file reports
with `--------`.

## Code style (clang-format)

- Version cible : `clang-format` 17 (utilisée dans la CI).
- Formater : `./scripts/format.sh`
- Vérifier sans modifier : `./scripts/format-check.sh`
- CMake : `cmake --build build --target format` ou `--target format-check`
- CI : job GitHub Actions `clang-format` qui échoue si le formatage diverge.
