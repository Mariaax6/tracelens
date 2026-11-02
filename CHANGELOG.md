# Changelog

## 2.0.0
Major revision with breaking CLI, CSV, JSON and package changes. See `docs/RELEASE_NOTES.md` for the full list: snaplen-truncated decoding, tolerant timestamp ordering, exact nanoseconds, Linux SLL and raw IPv4, non-fatal limits, richer alerts and reports, coverage example and end-to-end CI verification.

Migration from 1.x: replace `<capture> <report> <ports> <seconds>` with `<capture> <report> --threshold <ports> --window <seconds>`. `summary.json` now nests counts under `capture` and `coverage` (`unsupported` is split into `nonIpv4` and `otherProtocol`), and `flows.csv` has new columns.

## 1.0.1
Fixed the release workflow's tag handling.

## 1.0.0
Initial educational implementation: classic PCAP over Ethernet/IPv4, directional flows, SYN port-diversity heuristic, HTML/CSV/JSON reports, offline build scripts.
