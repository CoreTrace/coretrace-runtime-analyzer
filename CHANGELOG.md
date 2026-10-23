# Changelog

Notable changes are grouped by release. See [all releases](https://github.com/CoreTrace/coretrace-runtime-analyzer/releases) for older versions.

## Unreleased

- Added repository contribution and community documentation.
- SARIF: `tool.driver.rules` lists each rule reported with a title and a description, and each
  result carries its confidence (`high`, `medium` or `low`).
- A vtable box whose only warning is `missing typeinfo`, as a valid `-fno-rtti` program logs, is
  now a `vtable-diagnostic` warning instead of a `vtable-corrupted` error.

## v0.1.0

- Initial runtime analysis tool with structured memory-error and vtable-misuse findings.
- Program execution is bounded by a timeout.
- Source compilation failures are reported without terminating the analyzer.

[Full v0.1.0 notes](https://github.com/CoreTrace/coretrace-runtime-analyzer/releases/tag/v0.1.0).
