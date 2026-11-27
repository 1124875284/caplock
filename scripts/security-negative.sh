#!/usr/bin/env bash
# End-to-end security boundary checks for the CLI. These are intentionally
# negative tests: a missing sink, ambiguous input, or unsafe path must fail
# closed. This script is local-only.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

TMP=$(mktemp -d "${TMPDIR:-/tmp}/caplock-security-negative.XXXXXX")
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

BIN="$TMP/bin/caplock"
FAKE_MCP="$TMP/bin/fake-mcp"
mkdir -p "$TMP/bin"

echo "== build =="
go build -trimpath -o "$BIN" ./cmd/caplock
go build -trimpath -o "$FAKE_MCP" ./examples/fake-mcp

checks=0
failures=0
case_index=0

pass() {
  checks=$((checks + 1))
  printf '  ok   %s\n' "$1"
}

fail() {
  checks=$((checks + 1))
  failures=$((failures + 1))
  printf '  FAIL %s\n' "$1"
}

expect_contains() {
  local label=$1
  local file=$2
  local pattern=$3
  if grep -Fq -- "$pattern" "$file"; then
    pass "$label"
  else
    fail "$label (missing: $pattern)"
  fi
}

run_case() {
  local expected=$1
  local label=$2
  local input=$3
  shift 3

  case_index=$((case_index + 1))
  local stdout="$TMP/case-$case_index.stdout"
  local stderr="$TMP/case-$case_index.stderr"
  local code
  set +e
  if [ -n "$input" ]; then
    "$@" < "$input" >"$stdout" 2>"$stderr"
  else
    "$@" >"$stdout" 2>"$stderr"
  fi
  code=$?
  set -e

  if [ "$code" -eq "$expected" ]; then
    pass "$label (exit $code)"
  else
    fail "$label (exit $code, expected $expected)"
    sed -n '1,12p' "$stderr" >&2 || true
  fi
  LAST_STDOUT=$stdout
  LAST_STDERR=$stderr
}

cat >"$TMP/unsafe-policy.yaml" <<'EOF'
apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: unsafe
spec:
  defaults:
    effect: allow
  rules: []
EOF

cat >"$TMP/csv-mapping.yaml" <<'EOF'
version: 1
inputFormat: csv
fields:
  time: time
  policy: policy
  subject: subject
  tool: tool
  capabilities: capabilities
  decision.effect: effect
EOF

cat >"$TMP/missing-field.csv" <<'EOF'
time,policy,subject,tool,capabilities
2026-11-20T10:15:00Z,finance-agent,finance-analyst,read_file,read
EOF

cat >"$TMP/bad-time.csv" <<'EOF'
time,policy,subject,tool,capabilities,effect
not-a-time,finance-agent,finance-analyst,read_file,read,allow
EOF

cat >"$TMP/jsonl-mapping.yaml" <<'EOF'
version: 1
inputFormat: jsonl
fields:
  time: time
  policy: policy
  subject: subject
  tool: tool
  capabilities: capabilities
  decision.effect: effect
  args: args
  argsHash: argsHash
EOF

cat >"$TMP/bad-args-hash.jsonl" <<'EOF'
{"time":"2026-11-20T10:15:00Z","policy":"finance-agent","subject":"finance-analyst","tool":"read_file","capabilities":"read","effect":"allow","args":{"path":"/tmp/report.txt"},"argsHash":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}
EOF

echo "== policy gates =="
run_case 1 "strict lint rejects default allow" "" "$BIN" lint "$TMP/unsafe-policy.yaml" --strict
expect_contains "lint reports the default-allow warning" "$LAST_STDOUT" "default"

echo "== runtime obligation sinks =="
run_case 2 "missing --audit fails closed" "" \
  "$BIN" proxy --policy demo/fixtures/runtime-policy.yaml --subject finance-analyst \
  --alert "$TMP/missing-audit.alert.jsonl" -- "$FAKE_MCP"
expect_contains "audit error names the missing flag" "$LAST_STDERR" "pass --audit"

run_case 2 "missing --alert fails closed" "" \
  "$BIN" proxy --policy demo/fixtures/runtime-policy.yaml --subject finance-analyst \
  --audit "$TMP/missing-alert.audit.jsonl" -- "$FAKE_MCP"
expect_contains "alert error names the missing flag" "$LAST_STDERR" "pass --alert"

run_case 2 "missing --rate-limit fails closed" "" \
  "$BIN" proxy --policy demo/fixtures/obligation-policy.yaml --subject finance-analyst \
  --audit "$TMP/missing-rate.audit.jsonl" --alert "$TMP/missing-rate.alert.jsonl" -- "$FAKE_MCP"
expect_contains "rate-limit error names the missing flag" "$LAST_STDERR" "pass --rate-limit"

run_case 2 "audit and alert cannot share a path" "" \
  "$BIN" proxy --policy demo/fixtures/runtime-policy.yaml --subject finance-analyst \
  --audit "$TMP/shared.jsonl" --alert "$TMP/shared.jsonl" -- "$FAKE_MCP"
expect_contains "shared sink error is explicit" "$LAST_STDERR" "different files"

run_case 2 "full trace requires a trace path" "" \
  "$BIN" proxy --policy demo/fixtures/runtime-policy.yaml --subject finance-analyst \
  --audit "$TMP/trace-missing.audit.jsonl" --alert "$TMP/trace-missing.alert.jsonl" \
  --trace-arguments full -- "$FAKE_MCP"
expect_contains "trace option error is explicit" "$LAST_STDERR" "requires --trace"

if ln -s "$TMP/symlink-target.jsonl" "$TMP/symlink-trace.jsonl" 2>/dev/null; then
  run_case 3 "symlinked trace is rejected" "" \
    "$BIN" proxy --policy demo/fixtures/runtime-policy.yaml --subject finance-analyst \
    --audit "$TMP/symlink.audit.jsonl" --alert "$TMP/symlink.alert.jsonl" \
    --trace "$TMP/symlink-trace.jsonl" -- "$FAKE_MCP"
  expect_contains "symlink rejection is explicit" "$LAST_STDERR" "symlink"
else
  fail "could not create symlink fixture"
fi

echo "== runtime privacy =="
run_case 0 "redaction obligations execute" demo/fixtures/obligation-calls.jsonl \
  "$BIN" proxy --policy demo/fixtures/obligation-policy.yaml --subject finance-analyst \
  --audit "$TMP/privacy.audit.jsonl" --alert "$TMP/privacy.alert.jsonl" \
  --trace "$TMP/privacy.trace.jsonl" --trace-arguments full \
  --rate-limit 10/1m -- "$FAKE_MCP"
if grep -Eq 'raw-token|raw-password|second-token|second-password' \
  "$TMP/privacy.audit.jsonl" "$TMP/privacy.alert.jsonl" "$TMP/privacy.trace.jsonl"; then
  fail "runtime sinks leaked raw fixture secrets"
else
  pass "runtime sinks contain no raw fixture secrets"
fi
if grep -Fq '[REDACTED]' "$TMP/privacy.trace.jsonl"; then
  pass "full trace records redaction markers"
else
  fail "full trace does not record redaction markers"
fi

echo "== historical import =="
run_case 2 "import rejects a missing required field" "" \
  "$BIN" import "$TMP/missing-field.csv" --mapping "$TMP/csv-mapping.yaml" -o "$TMP/missing-field.trace.jsonl"
expect_contains "missing-field error is explicit" "$LAST_STDERR" "required field decision.effect"

run_case 2 "import rejects a malformed timestamp" "" \
  "$BIN" import "$TMP/bad-time.csv" --mapping "$TMP/csv-mapping.yaml" -o "$TMP/bad-time.trace.jsonl"
expect_contains "bad-time error is explicit" "$LAST_STDERR" "RFC3339"

run_case 2 "import rejects an argsHash mismatch" "" \
  "$BIN" import "$TMP/bad-args-hash.jsonl" --mapping "$TMP/jsonl-mapping.yaml" -o "$TMP/bad-hash.trace.jsonl"
expect_contains "argsHash mismatch is explicit" "$LAST_STDERR" "argsHash does not match"

if ln -s "$TMP/import-target.jsonl" "$TMP/import-symlink.jsonl" 2>/dev/null; then
  run_case 3 "import rejects a symlinked output" "" \
    "$BIN" import demo/fixtures/history.csv --mapping demo/fixtures/history-mapping.yaml -o "$TMP/import-symlink.jsonl"
  expect_contains "import symlink rejection is explicit" "$LAST_STDERR" "symlink"
else
  fail "could not create import symlink fixture"
fi

printf '\nsecurity negative checks: %d checks, %d failures.\n' "$checks" "$failures"
if [ "$failures" -ne 0 ]; then
  exit 1
fi
