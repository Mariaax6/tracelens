## TraceLens 2.0.0

Major revision. **Breaking changes:** command-line syntax, CSV columns, JSON schema and Java package name.

- Snaplen-truncated records are decoded when their headers are complete (previously every such packet was discarded as malformed).
- Out-of-order timestamps are counted instead of aborting the analysis; detection uses a monotonic clock.
- Timestamps are exact integer nanoseconds instead of floating point.
- New link types: Linux cooked capture (SLL, from `tcpdump -i any`) and raw IPv4. PCAPNG input gets a clear conversion hint.
- Reaching the flow or pair limits no longer aborts: the analysis continues and the report says what was left out. Per-pair detection memory is bounded by the number of ports.
- Every record is classified exactly once (decoded, non-IPv4, other protocol, malformed, fragment).
- Named options `--threshold`, `--window`, `--html-rows`, `--fail-on-alert`, `--version`.
- Alerts include window start and sample ports; flows record TCP flags; the JSON summary includes the input SHA-256, parameters, capture span and alert details.
- HTML report with light/dark themes and an honest bounded preview; CSV with protocol names, flags and UTC times.
- New `coverage.pcap` example, `demo.sh`, end-to-end checks in CI, Dependabot and a SHA-256 checksum published with the JAR.

Requires a Java 17+ runtime. This is an educational tool; see the README for unsupported formats and interpretation limits.
