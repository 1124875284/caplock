#!/usr/bin/env bash
# Verify that the committed demo outputs, screenshots, and README references are
# internally consistent. This does not regenerate or deploy anything.
set -u
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

OUT="$ROOT/demo/output"
SHOTS="$ROOT/demo/screenshots"
failures=0
checks=0

pass() {
  checks=$((checks + 1))
  printf '  ok   %s\n' "$1"
}

fail() {
  checks=$((checks + 1))
  failures=$((failures + 1))
  printf '  FAIL %s\n' "$1"
}

printf 'Demo output\n'
if [ ! -d "$OUT" ]; then
  fail "demo/output is missing; run demo/run.sh"
else
  pass "demo/output exists"
fi

scenario_count=0
for dir in "$OUT"/*; do
  [ -d "$dir" ] || continue
  name=$(basename "$dir")
  [ "$name" = "bin" ] && continue
  [ -f "$dir/title.txt" ] || continue
  scenario_count=$((scenario_count + 1))
  expected=$(cat "$dir/expected-exit.txt" 2>/dev/null || true)
  actual=$(cat "$dir/exit-code.txt" 2>/dev/null || true)
  if [ -n "$expected" ] && [ "$expected" = "$actual" ]; then
    pass "$name exit $actual"
  else
    fail "$name exit ${actual:-missing} (expected ${expected:-missing})"
  fi
  if [ -f "$dir/card.html" ]; then
    pass "$name card.html"
  else
    fail "$name card.html missing"
  fi
done

if [ "$scenario_count" -eq 33 ]; then
  pass "scenario count 33"
else
  fail "scenario count $scenario_count (expected 33)"
fi

printf '\nEvidence artifacts\n'
if grep -q 'Result: PASS (50/50 cases)' "$OUT/14-test/stdout.txt" 2>/dev/null; then
  pass "50/50 attack regression passed"
else
  fail "50/50 attack regression evidence missing"
fi
if grep -q 'Result: FAIL (0/50 cases)' "$OUT/15-test-fail/stdout.txt" 2>/dev/null; then
  pass "permissive-policy failure is visible"
else
  fail "permissive-policy failure evidence missing"
fi
if grep -q 'Summary: servers=20 tools=20 sources=3 sinks=9 paths=10' "$OUT/29-attack-graph/stdout.txt" 2>/dev/null; then
  pass "attack graph evaluated 20-server inventory"
else
  fail "attack graph evidence missing"
fi
if grep -q 'fail-on-exposed: exit 1 (expected)' "$OUT/29-attack-graph/stdout.txt" 2>/dev/null; then
  pass "attack graph exposure gate is visible"
else
  fail "attack graph exposure gate missing"
fi
if grep -q 'review-required' "$OUT/session-candidates.yaml" 2>/dev/null; then
  pass "trace-generated corpus candidates require review"
else
  fail "trace-generated corpus evidence missing"
fi
if grep -q 'Result: PASS (2/2 cases)' "$OUT/30-trace-corpus/stdout.txt" 2>/dev/null; then
  pass "trace-generated candidate corpus executes"
else
  fail "trace-generated candidate corpus evidence missing"
fi
if grep -q 'CHANGED' "$OUT/31-log-import/stdout.txt" 2>/dev/null || grep -q 'unchanged=1 changed=1' "$OUT/31-log-import/stdout.txt" 2>/dev/null; then
  pass "imported historical log replays"
else
  fail "imported historical log evidence missing"
fi
if grep -q '\[WEAKENED\]' "$OUT/25-replay-weakened/stdout.txt" 2>/dev/null; then
  pass "weakened replay is visible"
else
  fail "weakened replay evidence missing"
fi
if grep -q '\[STRENGTHENED\]' "$OUT/26-replay-strengthened/stdout.txt" 2>/dev/null; then
  pass "strengthened replay is visible"
else
  fail "strengthened replay evidence missing"
fi
if [ -s "$OUT/17-report-html/report.html" ]; then
  pass "HTML report exists"
else
  fail "HTML report missing"
fi
if python3 -m json.tool "$OUT/loose.sarif" >/dev/null 2>&1; then
  pass "SARIF parses as JSON"
else
  fail "SARIF is invalid JSON"
fi
if grep -q 'forbid (principal, action, resource)' "$OUT/exports/policy.cedar" 2>/dev/null; then
  pass "Cedar export exists"
else
  fail "Cedar export missing"
fi
if python3 -m json.tool "$OUT/exports/policy.sdk.json" >/dev/null 2>&1; then
  pass "SDK export parses as JSON"
else
  fail "SDK export is invalid JSON"
fi
if grep -q 'runtimeBlocked' "$OUT/obligation.audit.jsonl" 2>/dev/null && grep -q 'rate_limit exceeded' "$OUT/obligation.audit.jsonl" 2>/dev/null; then
  pass "runtime rate limit is visible in audit"
else
  fail "runtime rate limit evidence missing"
fi
if grep -q 'Raw secret values present? no' "$OUT/32-proxy-obligations/stdout.txt" 2>/dev/null; then
  pass "runtime redaction privacy assertion recorded"
else
  fail "runtime redaction privacy assertion missing"
fi
if grep -q 'benchmark: PASS (20 synthetic servers, 50 scenarios)' "$OUT/33-benchmark/stdout.txt" 2>/dev/null; then
  pass "benchmark passes"
else
  fail "benchmark evidence missing"
fi

printf '\nPrivacy invariants\n'
privacy_fail=0
while IFS= read -r file; do
  [ -f "$file" ] || continue
  if grep -Eq 'outside@example.com|quarterly-secret|raw-token|raw-password|second-token|second-password' "$file"; then
    fail "raw argument leaked into $file"
    privacy_fail=$((privacy_fail + 1))
  fi
done < <(find "$OUT" -maxdepth 1 -type f \( -name '*.audit.jsonl' -o -name '*.trace.jsonl' \))
if [ "$privacy_fail" -eq 0 ]; then
  pass "audit/trace files contain argument hashes only"
fi
if grep -q 'Raw argument values present? no' "$OUT/23-trace-capture/stdout.txt" 2>/dev/null; then
  pass "trace privacy assertion recorded"
else
  fail "trace privacy assertion missing"
fi

printf '\nSchemas\n'
if go test ./internal/trace -run Published -count=1 >/dev/null 2>&1; then
  pass "trace/replay schema tests"
else
  fail "trace/replay schema tests"
fi
if python3 -m json.tool schemas/trace.schema.json >/dev/null 2>&1; then
  pass "trace schema parses"
else
  fail "trace schema does not parse"
fi
if python3 -m json.tool schemas/replay.schema.json >/dev/null 2>&1; then
  pass "replay schema parses"
else
  fail "replay schema does not parse"
fi
if go test ./internal/attackgraph ./internal/logimport -run Published -count=1 >/dev/null 2>&1; then
  pass "attack-graph and import-mapping schema tests"
else
  fail "attack-graph and import-mapping schema tests"
fi
if python3 -m json.tool schemas/attackgraph.schema.json >/dev/null 2>&1; then
  pass "attack graph schema parses"
else
  fail "attack graph schema does not parse"
fi
if python3 -m json.tool schemas/import-mapping.schema.json >/dev/null 2>&1; then
  pass "import mapping schema parses"
else
  fail "import mapping schema does not parse"
fi

printf '\nScreenshots and README references\n'
missing_shots=0
missing_refs=0
for card in "$OUT"/*/card.html; do
  [ -f "$card" ] || continue
  name=$(basename "$(dirname "$card")")
  if [ -s "$SHOTS/$name.png" ]; then
    pass "screenshot $name.png"
  else
    fail "screenshot $name.png missing"
    missing_shots=$((missing_shots + 1))
  fi
  if grep -Fq "(demo/screenshots/$name.png)" README.md; then
    pass "README references $name.png"
  else
    fail "README does not reference $name.png"
    missing_refs=$((missing_refs + 1))
  fi
done

printf '\nDemo verification: %d checks, %d failures.\n' "$checks" "$failures"
if [ "$failures" -ne 0 ] || [ "$missing_shots" -ne 0 ] || [ "$missing_refs" -ne 0 ]; then
  exit 1
fi
