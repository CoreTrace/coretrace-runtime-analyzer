# Contributing to CoreTrace Runtime Analyzer

## Local setup

Follow the [source build](README.md#from-source) with LLVM/Clang 20 and the matching CMake package paths. Then run:

```bash
cmake --build build --parallel
ctest --test-dir build --output-on-failure
./scripts/format-check.sh
```

`./scripts/format.sh` applies the C++ format. Include a minimal reproducer for changes to diagnostics or runtime behavior, update the relevant usage documentation, and state the validation commands in your pull request. Use an English Conventional Commit subject.

The analyzer compiles and runs its input program with the caller's privileges. Read [SECURITY.md](SECURITY.md) before handling untrusted inputs or reporting a vulnerability.
