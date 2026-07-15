# Implement `runtime-analyzer` Minimal Execution Tool

## Summary

Implement the `runtime-analyzer` executable for `coretrace-runtime-analyzer`.

The tool must use `coretrace-compiler` in library mode to compile an instrumented
C/C++ source, execute the generated binary, capture stdout/stderr, and produce a
basic runtime collection summary.

## Scope

- Build the executable as `runtime-analyzer`.
- Integrate `coretrace-compiler` through its library API.
- Compile forwarded C/C++ arguments into an instrumented executable.
- Execute the generated binary.
- Capture runtime stdout and stderr.
- Report the executed binary exit code.
- Collect and summarize basic CoreTrace runtime events:
  - CoreTrace log lines
  - function entry events
  - function exit events
  - allocation events
  - bounds errors
  - leak reports
  - vtable diagnostics
  - warnings and errors
- Support analyzer options for:
  - output binary path
  - runtime arguments
  - environment variables
  - event display
  - captured output display
- Support `--test-dir` batch mode by compiling and running each source file as an
  independent instrumented binary.

## Architecture Notes

The implementation should keep the CLI entry point small and delegate behavior to
a runtime analyzer module. Compiler integration, process execution, stream
capture, and event collection should remain separated so each responsibility can
evolve independently.

The tool should call `coretrace-compiler` through the library API instead of
shelling out to a wrapper command. This keeps the integration generic, avoids
hardcoded compiler behavior, and makes the analyzer easier to reuse from tests or
future orchestration layers.

Batch mode should compile each source independently rather than linking multiple
test files together. This avoids symbol collisions between files that each define
their own `main` function and keeps failures isolated per source.

## Acceptance Criteria

- `cmake --build build --target runtime-analyzer` builds successfully.
- `runtime-analyzer` compiles a C/C++ source into an instrumented binary.
- The generated binary exists and is executable.
- The tool runs the generated binary.
- The tool reports the instrumented binary exit code.
- The tool captures stdout and stderr from the executed binary.
- The tool prints a basic runtime collection summary.
- `--test-dir` discovers supported C/C++ sources and runs each one independently.
- Runtime failures in batch mode are reported without stopping the full batch.
- A strict mode exists for treating non-zero test binary exits as analyzer
  failures.

## Out of Scope

- Python BTP validation scripts.
- Feature-specific proof scripts such as F4 or F11.
- Advanced report formats.
- Deep semantic analysis.
- A full runtime policy engine.

## Proposed Commit Message

```text
feat(runtime): implement minimal runtime analyzer execution
```
