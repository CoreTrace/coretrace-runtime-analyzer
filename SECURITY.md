# Security Policy

## Reporting a Vulnerability

Do not open a public issue for a vulnerability. Report it privately through GitHub's
private vulnerability reporting for this repository:

https://github.com/CoreTrace/coretrace-runtime-analyzer/security/advisories/new

Include:

- the affected commit, tag or release;
- reproduction steps;
- the input program, or a sanitized proof of concept;
- expected and observed behavior;
- an impact assessment if known.

## Response Targets

| Step | Target |
| --- | --- |
| Acknowledge report | 5 business days |
| Initial triage | 10 business days |
| Remediation plan | After triage, based on severity |
| Public disclosure | After the fix, or by coordinated disclosure agreement |

## Supported Versions

The project is pre-1.0. Security fixes land on `main` and in the latest release.

## Scope

`runtime-analyzer` compiles and runs the program it is given: the instrumented binary runs with
the analyzer's privileges, on the analyzer's machine. Only analyze programs you would run
yourself. Findings come from the CoreTrace runtime built into the program; a vulnerability in the
instrumentation itself belongs to [coretrace-compiler](https://github.com/CoreTrace/coretrace-compiler).
