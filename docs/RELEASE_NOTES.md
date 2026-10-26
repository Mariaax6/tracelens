## Version 1.0.1

Initial educational Java 17 implementation, with AI-assisted development explicitly documented.

- Source code, deterministic lab examples and regression checks.
- Offline build scripts for PowerShell and POSIX shells; no external Java runtime libraries.
- HTML and machine-readable reports.
- English README and Spanish learning guide.

The release JAR is rebuilt and tested by the release workflow. A Java 17+ runtime is required. This is an educational tool; see README for unsupported formats, policy assumptions and interpretation limits.

Packaging fix: preserve the GitHub tag environment variable when generating the publication command. Version 1.0.0 built and passed verification but its automated publication failed; 1.0.1 corrects that workflow.
