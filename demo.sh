#!/usr/bin/env sh
# Builds (if needed) and runs every bundled example, asserting exit codes and headline counts.
set -eu
cd "$(dirname "$0")"
[ -f dist/tracelens.jar ] || sh build.sh
JAR=dist/tracelens.jar
expect() {
  want_code=$1; want_text=$2; shift 2
  set +e; out=$(java -jar "$JAR" "$@" 2>&1); got=$?; set -e
  if [ "$got" -ne "$want_code" ]; then echo "FAIL: expected exit $want_code, got $got: $*" >&2; echo "$out" >&2; exit 1; fi
  case "$out" in *"$want_text"*) ;; *) echo "FAIL: output lacks '$want_text': $*" >&2; echo "$out" >&2; exit 1 ;; esac
  echo "ok   exit $got   $*"
}
expect 0 "RECORDS=33 DECODED=33 FLOWS=19 ALERTS=1" examples/demo.pcap         reports/demo
expect 1 "ALERTS=1"                                examples/demo.pcap         reports/demo-ci --fail-on-alert
expect 0 "RECORDS=20 DECODED=20 FLOWS=20 ALERTS=0" examples/slow-diverse.pcap reports/slow-diverse --fail-on-alert
expect 0 "RECORDS=9 DECODED=4 FLOWS=3 ALERTS=0"    examples/coverage.pcap     reports/coverage
expect 2 "Not a classic PCAP"                      README.md                  reports/none
echo "Open reports/demo/report.html to inspect the results."
