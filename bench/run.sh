#!/usr/bin/env bash
# Local-only benchmark harness: 20 synthetic MCP servers and the 50-case corpus.
# It does not install packages, contact remote MCP servers, or deploy anything.
set -u
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1
TMP=$(mktemp -d "${TMPDIR:-/tmp}/caplock-bench.XXXXXX")
cleanup() { find "$TMP" -depth -delete 2>/dev/null || true; }
trap cleanup EXIT

baseline_value() {
  sed -n "s/^$1=//p" bench/baseline.txt
}

expected_graph=$(baseline_value graph_summary)
expected_corpus=$(baseline_value corpus)
if [ -z "$expected_graph" ] || [ -z "$expected_corpus" ]; then
  echo "bench: bench/baseline.txt is incomplete" >&2
  exit 1
fi

echo "== build =="
go build -trimpath -o "$TMP/caplock" ./cmd/caplock || exit 1

echo "== generate 20-server lockfile =="
go run ./bench/gen -output "$TMP/caplock.lock" || exit 1

echo "== attack graph =="
"$TMP/caplock" graph examples/policy/caplock.yaml \
  --lockfile "$TMP/caplock.lock" \
  --subject finance-analyst \
  --format text --max-paths 200 | tee "$TMP/graph.txt" || exit 1

echo "== permission matrix =="
"$TMP/caplock" matrix examples/policy/caplock.yaml \
  --lockfile "$TMP/caplock.lock" \
  --subject finance-analyst --format text | tee "$TMP/matrix.txt" || exit 1

echo "== 50-case regression =="
"$TMP/caplock" test examples/policy/caplock.yaml | tee "$TMP/test.txt" || exit 1

grep -Fq "Summary: $expected_graph" "$TMP/graph.txt" || {
  echo "bench: graph baseline drift" >&2
  echo "  expected: $expected_graph" >&2
  grep -F 'Summary:' "$TMP/graph.txt" >&2 || true
  exit 1
}
grep -Fq "Result: $expected_corpus" "$TMP/test.txt" || {
  echo "bench: corpus baseline drift; expected $expected_corpus" >&2
  grep -E 'Result:' "$TMP/test.txt" >&2 || true
  exit 1
}
printf '\nbenchmark: PASS (20 synthetic servers, 50 scenarios)\n'
