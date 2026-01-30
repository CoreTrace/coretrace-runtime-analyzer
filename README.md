# coretrace-tool-template
Standardized template repository for building CoreTrace tools with a unified architecture, CI pipeline, and best practices for scalable static and dynamic analysis tooling.

## Code style (clang-format)

- Version cible : `clang-format` 17 (utilisée dans la CI).
- Formater : `./scripts/format.sh`
- Vérifier sans modifier : `./scripts/format-check.sh`
- CMake : `cmake --build build --target format` ou `--target format-check`
- CI : job GitHub Actions `clang-format` qui échoue si le formatage diverge.
