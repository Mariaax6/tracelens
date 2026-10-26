# Validation record

Date: 26 October 2026. Windows; local JDK 21.0.6, compiled with --release 17.

## Executed

- TraceLens: **24 component checks passed**.
- HostBaseline: **17 component checks passed**.
- End-to-end and output checks: **29 passed**.
- Both demo.ps1 runners completed successfully; both executable JARs were rebuilt after the final source changes.
- TraceLens synthetic PCAP: decoded independently with installed Wireshark tshark. Frame count and IP/transport fields agreed with the generated fixture. No frame was reported with a bad TCP checksum when verification was enabled.

## End-to-end checks

- TraceLens JAR exit 0
- TraceLens complete demo counts
- CSV conserves 33 packets across 19 flows
- Slow diverse negative control
- Invalid PCAP returns 2 without successful report
- Invalid threshold rejected
- HostBaseline risky exit 1
- HostBaseline risky JSON counts
- HostBaseline risky evidence hashes
- Drift comparison identifies six changed checks
- HostBaseline hardened exit 0
- HostBaseline hardened JSON counts
- HostBaseline hardened evidence hashes
- HostBaseline incomplete exit 3
- HostBaseline incomplete JSON counts
- HostBaseline incomplete evidence hashes
- Absent snapshot directory returns 2
- Untrusted snapshot values escaped in HTML
- JSON preserves observed evidence without breaking syntax
- Local link exists: tracelens/reports/demo/report.html
- Local link exists: tracelens/reports/slow-diverse/report.html
- Local link exists: tracelens/README.md
- Local link exists: hostbaseline/reports/risky/report.html
- Local link exists: hostbaseline/reports/hardened/report.html
- Local link exists: hostbaseline/reports/incomplete/report.html
- Local link exists: hostbaseline/README.md
- Local link exists: EMPIEZA-AQUI.md
- tracelens help
- hostbaseline help

## Limits of verification

- No live traffic was captured and no real Linux host was audited.
- No network scan, system-setting change, installation, publication or account operation was performed for these projects.
- HTML was parsed and local links were checked; browser visual review was not completed because computer control stopped when the current browser URL could not be verified confidently.
- Linux/macOS build scripts and the prepared GitHub Actions workflow have not been run here.
- No performance benchmark, independent labelled attack corpus, detection precision/recall, compliance assessment or deployment result is claimed.
- Optional Maven/IDE import metadata was supplied but not used for the verified offline build.
- Unit tests are framework-free Java checks; the reported count is checks, not a claim of exhaustive test coverage.
