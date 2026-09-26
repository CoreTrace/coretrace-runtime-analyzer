# coretrace-runtime-analyzer

Runs a C or C++ program with CoreTrace instrumentation and reports the memory errors it hits as
findings with a source location, as text or as a SARIF log.

`runtime-analyzer` compiles the program through
[coretrace-compiler](https://github.com/CoreTrace/coretrace-compiler)'s library API with
instrumentation enabled, runs the instrumented binary with a timeout and its stdin on `/dev/null`,
captures its output, and turns each report of the CoreTrace runtime into a finding.

## What It Detects

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

The memory rules come from the `alloc` and `bounds` modules, which the default module set
enables. The vtable rules come from the `vtable` module's diagnostics
(`--ct-modules=alloc,vtable --ct-vtable-diag`): each box the runtime logs at `WARN` level is one
finding, its message listing the box's warnings and its rule the most specific one. Boxes logged
at `INFO` level are tracing and produce no finding.

Sites carry the path the source was compiled from, so run the analyzer from the directory the
static analyzers report paths from.

## Install

### From a release

Each [release](https://github.com/CoreTrace/coretrace-runtime-analyzer/releases) carries a
self-contained Linux archive per architecture, `runtime-analyzer-<version>-linux-amd64.tar.gz`
and `runtime-analyzer-<version>-linux-arm64.tar.gz`, each with its `.sha256`:

```zsh
sha256sum -c runtime-analyzer-v0.1.0-linux-amd64.tar.gz.sha256
tar -xzf runtime-analyzer-v0.1.0-linux-amd64.tar.gz
./runtime-analyzer-v0.1.0-linux-amd64/bin/runtime-analyzer --version
```

The tree holds `bin/runtime-analyzer`, the LLVM libraries it links and the instrumentation
runtime archives in `lib/`, Clang's own headers in `lib/clang/<version>/include`, and the
library with its headers. Everything is found relative to the CLI's own location, so the tree can
be moved. No clang and no LLVM have to be installed: the CLI points coretrace-compiler at the
shipped headers unless `CT_CLANG` names another clang.

The archive is built on Ubuntu 22.04 and runs on it and on every newer distribution (Debian 12,
RHEL 9 and rebuilds, Ubuntu 24.04...). What stays the system's is a C++ build environment to
link each instrumented program against the runtime, which is C++: `g++` on Debian and Ubuntu,
`gcc-c++` on RHEL, as for building any C++ program.

### From source

Needs CMake 3.16 or later, a C++20 compiler, LLVM and Clang 19 or later with their CMake
packages, and Python 3 for the tests. coretrace-compiler is fetched at configure time, at the
release tag pinned in `CMakeLists.txt`.

```zsh
# macOS: brew install llvm@20. Debian/Ubuntu: /usr/lib/llvm-20/lib/cmake/{llvm,clang}.
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_DIR=$(brew --prefix llvm@20)/lib/cmake/llvm \
  -DClang_DIR=$(brew --prefix llvm@20)/lib/cmake/clang
cmake --build build --parallel
cmake --install build --prefix /opt/coretrace   # optional
```

Configuration fails against an LLVM older than `LLVM_MIN_REQUIRED_VERSION` (19).

## Usage

```zsh
runtime-analyzer [options] -- <compiler args>
```

Arguments before `--` belong to `runtime-analyzer`. Arguments after `--` are forwarded to
`coretrace-compiler` and then to Clang. The analyzer enables instrumentation through the
`compilerlib::compile(..., instrument=true)` API, so `--instrument` is optional and ignored if it
is present after `--`.

### Example

`test/findings/heap_overflow_write.c` writes one element past a `malloc`'d array of four:

```c
int main(void)
{
    int* values = malloc(4 * sizeof(int));
    values[4] = 1;
    free(values);
    return 0;
}
```

```console
$ cd test
$ runtime-analyzer -- --ct-modules=alloc,bounds findings/heap_overflow_write.c
runtime-analyzer: binary=runtime-analyzer.out
runtime-analyzer: exit_code=134
runtime-analyzer: timed_out=0
runtime-analyzer: findings=1
  findings/heap_overflow_write.c:7:15: error: heap-buffer-overflow WRITE of size 4 [heap-buffer-overflow, CWE-122]
    findings/heap_overflow_write.c:6:19: note: allocated here
runtime-analyzer: collection
  coretrace_lines=8
  ...
$ echo $?
1
```

`--format sarif` prints a SARIF 2.1.0 log instead of the text summary: one result per finding
with `ruleId`, `level`, `message.text` and `properties.cwe`, the faulting access as
`locations[0]` and the allocation site as `relatedLocations[0]` (`id` 0, "allocated here"). In
`--test-dir` mode, the log holds the findings of every program in one run.

```console
$ runtime-analyzer --format sarif -- --ct-modules=alloc,bounds findings/heap_overflow_write.c
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "results": [
        {
          "level": "error",
          "locations": [ { "physicalLocation": { "artifactLocation": { "uri": "findings/heap_overflow_write.c" },
                                                 "region": { "startColumn": 15, "startLine": 7 } } } ],
          "message": { "text": "heap-buffer-overflow WRITE of size 4" },
          "properties": { "cwe": "CWE-122" },
          "relatedLocations": [ { "id": 0, "message": { "text": "allocated here" }, ... } ],
          "ruleId": "heap-buffer-overflow"
        }
      ],
      "tool": { "driver": { "name": "coretrace-runtime-analyzer", ... } }
    }
  ],
  "version": "2.1.0"
}
```

### Options

| Option | Effect |
|---|---|
| `-o, --output <path>` | instrumented binary path when the compiler args carry no `-o` |
| `--run-arg <value>` | argument passed to the instrumented binary (repeatable) |
| `--env NAME=VALUE` | environment variable set for the instrumented binary (repeatable) |
| `--cwd <path>` | working directory of the instrumented binary |
| `--timeout <seconds>` | kill the binary after this long; 60 by default, `0` disables the limit |
| `--format <text\|sarif>` | text summary (default) or SARIF log on stdout |
| `--show-output` | print the captured stdout and stderr after the summary |
| `--show-events` | print the collected CoreTrace event lines |
| `--no-run` | compile only |
| `--test-dir <path>` | run every C/C++ source under a directory (repeatable, see below) |
| `--output-dir <path>` | artifact directory used by `--test-dir` (`runtime-analyzer-artifacts` by default) |
| `--strict-test-exit` | in batch mode, a non-zero program exit raises the status to at least 1 |
| `--version` | print the version and exit |

### Exit Status

The exit status is the analyzer's verdict. The program's own status is reported as `exit_code=`.

| Status | Meaning |
|---|---|
| `0` | the program was built and ran, and reported no finding |
| `1` | at least one finding was reported |
| `2` | the program could not be built or run, timed out without findings, or the arguments are invalid |

In batch mode the status is the worst of all the tests, and `--strict-test-exit` raises it to at
least `1` when a program exits non-zero.

### Timeout

Each run is bounded by `--timeout`. The program starts in its own process group with its stdin on
`/dev/null`, so a program waiting for input ends at EOF. When the deadline passes, the whole group
is killed, the output captured so far is still parsed for findings, the summary reports
`timed_out=1`, and the diagnostics say `program timed out after N s`.

## Library Use

The CLI is a thin `main()` over `coretrace::runtime_analyzer::Run()`, declared in
`include/runtime_analyzer.hpp`. A CMake project can fetch this repository and link
`coretrace::runtime-analyzer_lib`; `AnalyzerResult::findings` then holds the findings of a run,
`AnalyzerOptions::timeout` bounds it, and `AnalyzerResult::timed_out` reports a killed run. The
version is `coretrace::runtime_analyzer::kVersion`, from the generated
`runtime_analyzer_version.hpp`. The CTest suite is registered by the top-level project only, so
consumers do not inherit it.

## Batch Test Directory Mode

Use `--test-dir <path>` to run every `.c`, `.cc`, `.cpp`, and `.cxx` source under a test directory.
Each source is compiled and executed as a separate instrumented binary, which avoids linker
collisions between test files that each define `main`.

Arguments after `--` are shared compiler/CoreTrace flags for every test file. Batch mode keeps going
after compile failures, runtime failures and timeouts, marks them `[COMPILE]`, `[RUNTIME]` and
`[TIMEOUT]` in the per-test lines, prints each test's findings under its line, and counts them in
the batch summary. Add `--strict-test-exit` if a non-zero test binary exit should make the analyzer
return a non-zero exit code.

```zsh
runtime-analyzer --test-dir test --timeout 10 --output-dir /tmp/runtime-analyzer-tests -- --ct-modules=all
```

## Tests

```zsh
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
| `version` | `--version` prints the `project()` version |
| `llvm_floor` | configuration fails against an LLVM below the floor |
| `shipped_toolchain_unit` | the CLI points coretrace-compiler at the Clang headers shipped next to it, unless `CT_CLANG` is set |
| `install_layout` | `cmake --install` lays out the CLI, library, headers and Clang headers, and the installed CLI builds and runs a program |

The `Build` workflow runs this suite on Ubuntu 24.04 and macOS against LLVM 20 for every push and
pull request. `clang-format` (version 17) is checked by the `clang-format` workflow.

## Releasing

1. Set the version in `project(... VERSION x.y.z ...)` in `CMakeLists.txt` and merge it.
2. Tag the commit `vx.y.z` and push the tag.

The `Release` workflow checks that the tag matches the project version, then builds the
archives with `Dockerfile.release` for amd64 and arm64: an Ubuntu 22.04 base with GCC 13 and
LLVM 20, the test suite, `cmake --install` with the LLVM libraries and Clang headers shipped,
`patchelf` for the rpaths, and a run of `test/release/check-analysis.sh` on bare Ubuntu 22.04,
Debian 12, Rocky Linux 9 and Ubuntu 24.04 images with only `g++` installed. The archives and
their `.sha256` are attached to the GitHub Release. The same build runs on every pull request
that touches the release files, without publishing.

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). To report a vulnerability, see
[SECURITY.md](SECURITY.md).
