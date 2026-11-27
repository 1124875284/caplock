#!/usr/bin/env bash
# Reproduce every Caplock CLI, policy, proxy, trace, replay, and schema demo.
# This script is local-only: it never deploys, publishes, or contacts a remote
# MCP server. The only child process is examples/fake-mcp.
set -u
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

OUT="$ROOT/demo/output"
FIXTURES="$ROOT/demo/fixtures"
BIN="$ROOT/bin/caplock"
FAKE_MCP="$OUT/bin/fake-mcp"

export CAPLOCK_BIN="$BIN"
export FAKE_MCP
export DEMO_OUT="$OUT"
export DEMO_FIXTURES="$FIXTURES"
export OPA_BIN="${OPA_BIN:-}"

if [ -d "$OUT" ]; then
  find "$OUT" -mindepth 1 -delete
fi
mkdir -p "$OUT/bin"

if ! go build -trimpath -ldflags '-s -w -X github.com/1124875284/caplock/internal/version.Version=0.1.0-dev-demo' -o "$BIN" ./cmd/caplock; then
  echo "demo: cannot build caplock" >&2
  exit 1
fi
if ! go build -trimpath -o "$FAKE_MCP" ./examples/fake-mcp; then
  echo "demo: cannot build fake MCP server" >&2
  exit 1
fi

failures=0
scenarios=0

record() {
  local id=$1
  local title=$2
  local group=$3
  local expected=$4
  local description=$5
  local command_text display
  command_text=$(cat)
  scenarios=$((scenarios + 1))

  local dir="$OUT/$id"
  mkdir -p "$dir"
  printf '%s\n' "$title" > "$dir/title.txt"
  printf '%s\n' "$group" > "$dir/group.txt"
  printf '%s\n' "$description" > "$dir/description.txt"
  printf '%s\n' "$expected" > "$dir/expected-exit.txt"
  printf '%s\n' "$command_text" > "$dir/raw-command.txt"

  display=$(printf '%s' "$command_text" | LC_ALL=C sed \
    -e 's|\$CAPLOCK_BIN|caplock|g' \
    -e 's|\$FAKE_MCP|demo/output/bin/fake-mcp|g' \
    -e 's|\$DEMO_FIXTURES|demo/fixtures|g' \
    -e 's|\$DEMO_OUT|demo/output|g')
  printf '%s\n' "$display" > "$dir/command.txt"

  printf '  %-28s ' "$id"
  bash -o pipefail -c "$command_text" > "$dir/stdout.txt" 2> "$dir/stderr.txt"
  local code=$?
  printf '%s\n' "$code" > "$dir/exit-code.txt"
  if [ "$code" -eq "$expected" ]; then
    printf 'ok (exit %s)\n' "$code"
  else
    printf 'UNEXPECTED exit %s (expected %s)\n' "$code" "$expected"
    failures=$((failures + 1))
  fi
}

record "01-overview" \
  "One binary, four reviewable layers" \
  "Overview" 0 \
  "The CLI exposes the facts, intent, evidence, and execution layers without a control plane or remote service." <<'COMMAND'
$CAPLOCK_BIN version
printf '\n'
$CAPLOCK_BIN --help
COMMAND

record "02-scan-static" \
  "Discover MCP servers without executing them" \
  "Facts layer" 0 \
  "Static scan reads project configuration only. It does not start an MCP child process unless --connect is explicit." <<'COMMAND'
$CAPLOCK_BIN scan examples/quickstart
COMMAND

record "03-scan-connected" \
  "Capture tools from a real MCP handshake" \
  "Facts layer" 0 \
  "Connected mode performs initialize and paginated tools/list against the bundled dependency-free fake server." <<'COMMAND'
$CAPLOCK_BIN scan examples/connected --connect
COMMAND

record "04-lock" \
  "Write a deterministic capability lockfile" \
  "Facts layer" 0 \
  "Tool descriptions and schemas are hashed, never stored. Capabilities are conservative review aids, not authorization proof." <<'COMMAND'
$CAPLOCK_BIN lock examples/connected --connect -o demo/output/connected.lock
printf '\nCaptured lockfile excerpt:\n'
sed -n '1,58p' demo/output/connected.lock
COMMAND

record "05-diff" \
  "Review tool manifest drift in CI" \
  "Facts layer" 1 \
  "A changed tool name produces a reviewable lockfile diff. The exit code becomes a pull-request gate." <<'COMMAND'
cp demo/output/connected.lock demo/output/connected-next.lock
LC_ALL=C perl -0pi -e 's/"name": "read_file"/"name": "read_file_v2"/' demo/output/connected-next.lock
$CAPLOCK_BIN diff demo/output/connected.lock demo/output/connected-next.lock --exit-code
COMMAND

record "06-lock-check" \
  "Fail a PR when the committed lockfile is stale" \
  "Facts layer" 1 \
  "lock --check regenerates the deterministic lockfile in memory and refuses to let a changed MCP command pass CI." <<'COMMAND'
mkdir -p demo/output/drift-project
cp examples/quickstart/.mcp.json examples/quickstart/caplock.lock demo/output/drift-project/
LC_ALL=C perl -0pi -e 's/server-github/server-github-latest/' demo/output/drift-project/.mcp.json
$CAPLOCK_BIN lock demo/output/drift-project --check -o demo/output/drift-project/caplock.lock
COMMAND

record "07-init" \
  "Start from a validated policy skeleton" \
  "Intent layer" 0 \
  "init writes a minimal caplock/v1alpha1 policy that can be linted, compiled, and tested immediately." <<'COMMAND'
mkdir -p demo/output/init-project
$CAPLOCK_BIN init demo/output/init-project
printf '\nStarter policy:\n'
sed -n '1,42p' demo/output/init-project/caplock.yaml
COMMAND

record "08-draft" \
  "Compile supported security statements, fail closed on ambiguity" \
  "Intent layer" 0 \
  "draft is a bounded English/Chinese template compiler. It never calls an LLM and rejects statements outside its documented grammar." <<'COMMAND'
$CAPLOCK_BIN draft examples/policy/security-brief.txt --name finance-draft --subject finance-analyst --parent orchestrator -o demo/output/draft.yaml
$CAPLOCK_BIN draft "$DEMO_FIXTURES/zh-security-brief.txt" --name finance-draft-zh --subject finance-analyst --parent orchestrator -o demo/output/draft-zh.yaml
printf '\nEnglish draft excerpt:\n'
sed -n '1,38p' demo/output/draft.yaml
printf '\nChinese draft rule IDs:\n'
grep -E '^    - id:' demo/output/draft-zh.yaml
COMMAND

record "09-templates" \
  "The drafting grammar is explicit and bounded" \
  "Intent layer" 0 \
  "This is the complete set of statements the first release can compile. Anything else is a review task, not a guess." <<'COMMAND'
$CAPLOCK_BIN draft --list-templates
COMMAND

record "10-lint" \
  "Block unsafe policy shapes before enforcement" \
  "Intent layer" 0 \
  "Strict lint validates both drafted policies and the checked-in finance policy. Errors block proxy startup; warnings block --strict CI runs." <<'COMMAND'
$CAPLOCK_BIN lint demo/output/draft.yaml --strict
$CAPLOCK_BIN lint demo/output/draft-zh.yaml --strict
$CAPLOCK_BIN lint examples/policy/caplock.yaml --strict
COMMAND

record "11-lint-gate" \
  "Turn a default-allow warning into a CI failure" \
  "Intent layer" 1 \
  "A deliberately permissive policy is structurally valid but unsafe. --strict makes the default-allow warning gate the change." <<'COMMAND'
$CAPLOCK_BIN lint "$DEMO_FIXTURES/loose-policy.yaml" --strict
COMMAND

record "12-compile" \
  "Compile source into deterministic Policy IR" \
  "Intent layer" 0 \
  "The IR is normalized, carries source locations, and is the single input to evaluation, reporting, export, and replay." <<'COMMAND'
$CAPLOCK_BIN compile examples/policy/caplock.yaml -o demo/output/policy.ir.json
printf '\nCompiled IR excerpt:\n'
sed -n '1,46p' demo/output/policy.ir.json
COMMAND

record "13-matrix" \
  "Review the subject-by-tool baseline allow matrix" \
  "Evidence layer" 0 \
  "The matrix joins captured tools with policy evaluation. Conditional rules remain visible instead of collapsing into a misleading boolean." <<'COMMAND'
$CAPLOCK_BIN matrix examples/policy/caplock.yaml \
  --lockfile demo/output/connected.lock \
  --subject finance-analyst
COMMAND

record "14-test" \
  "Run the 50-case attack regression corpus" \
  "Evidence layer" 0 \
  "The deterministic corpus covers prompt injection, tool poisoning, secret egress, privilege escalation, destructive actions, finance time windows, and unknown tools." <<'COMMAND'
$CAPLOCK_BIN test examples/policy/caplock.yaml \
  --lockfile demo/output/connected.lock \
  --subject finance-analyst > demo/output/evidence.txt
cat demo/output/evidence.txt
COMMAND

record "15-test-fail" \
  "A permissive policy exposes its blast radius" \
  "Evidence layer" 1 \
  "The same corpus against default-allow fails closed as a regression: 44 high/critical cases become reachable." <<'COMMAND'
$CAPLOCK_BIN test "$DEMO_FIXTURES/loose-policy.yaml" > demo/output/evidence-loose.txt
code=$?
sed -n '1,22p' demo/output/evidence-loose.txt
exit $code
COMMAND

record "16-report-text" \
  "Explain blocked, approval, and allowed attack paths" \
  "Evidence layer" 0 \
  "The text report names the rule or default decision for each path, summarizes blast radius, and checks tool coverage." <<'COMMAND'
$CAPLOCK_BIN report examples/policy/caplock.yaml \
  --lockfile demo/output/connected.lock \
  --subject finance-analyst > demo/output/report.txt
cat demo/output/report.txt
COMMAND

record "17-report-html" \
  "Open a self-contained attack-path report" \
  "Evidence layer" 0 \
  "The HTML report is dependency-free and local. The README screenshot captures the generated artifact itself, not a mockup." <<'COMMAND'
$CAPLOCK_BIN report examples/policy/caplock.yaml \
  --lockfile demo/output/connected.lock \
  --subject finance-analyst \
  --format html \
  -o demo/output/17-report-html/report.html
COMMAND

record "18-report-sarif" \
  "Feed policy gaps into code scanning" \
  "Evidence layer" 0 \
  "SARIF turns failed expectations, delegation violations, and tool-coverage gaps into standard code-scanning results." <<'COMMAND'
$CAPLOCK_BIN report "$DEMO_FIXTURES/loose-policy.yaml" \
  --format sarif \
  -o demo/output/loose.sarif
python3 -m json.tool demo/output/loose.sarif | sed -n '1,64p'
COMMAND

record "19-exports" \
  "Export Rego, Cedar, YAML, JSON, and SDK config" \
  "Execution layer" 0 \
  "Every export comes from the same Policy IR. Cedar rejects unsupported operators instead of silently approximating them; Rego is validated against a real OPA binary by an optional parity suite." <<'COMMAND'
mkdir -p demo/output/exports
$CAPLOCK_BIN export examples/policy/caplock.yaml --format rego -o demo/output/exports/policy.rego
$CAPLOCK_BIN export examples/policy/caplock.yaml --format yaml -o demo/output/exports/policy.yaml
$CAPLOCK_BIN export examples/policy/caplock.yaml --format json -o demo/output/exports/policy.json
$CAPLOCK_BIN export examples/policy/caplock.yaml --format sdk -o demo/output/exports/policy.sdk.json
$CAPLOCK_BIN export demo/fixtures/runtime-policy.yaml --format cedar -o demo/output/exports/policy.cedar
printf '\nGenerated artifacts:\n'
wc -l demo/output/exports/policy.rego demo/output/exports/policy.yaml demo/output/exports/policy.json demo/output/exports/policy.sdk.json demo/output/exports/policy.cedar
printf '\nCedar excerpt (approval is exported as forbid):\n'
sed -n '1,24p' demo/output/exports/policy.cedar
COMMAND

record "20-proxy-allow" \
  "Forward an allowed read-only call" \
  "Execution layer" 0 \
  "The proxy evaluates tools/call, forwards the request to the child MCP server, and returns the child result unchanged." <<'COMMAND'
$CAPLOCK_BIN proxy \
  --policy demo/fixtures/runtime-policy.yaml \
  --subject finance-analyst \
  --audit demo/output/proxy-allow.audit.jsonl \
  --alert demo/output/proxy-allow.alert.jsonl \
  -- "$FAKE_MCP" < "$DEMO_FIXTURES/read-call.jsonl"
COMMAND

record "21-proxy-deny" \
  "Stop a destructive call before the tool runs" \
  "Execution layer" 0 \
  "A denied call never reaches the child MCP server. The JSON-RPC error names the policy rule and any obligations the reference proxy cannot enforce." <<'COMMAND'
$CAPLOCK_BIN proxy \
  --policy demo/fixtures/runtime-policy.yaml \
  --subject finance-analyst \
  --audit demo/output/proxy-deny.audit.jsonl \
  --alert demo/output/proxy-deny.alert.jsonl \
  -- "$FAKE_MCP" < "$DEMO_FIXTURES/delete-call.jsonl"
COMMAND

record "22-proxy-approval" \
  "Approval is explicit: block by default, forward on opt-in" \
  "Execution layer" 0 \
  "require_approval is not silently treated as allow. Block mode stops the call; forward mode is an explicit operator choice recorded in audit." <<'COMMAND'
printf 'Block mode:\n'
$CAPLOCK_BIN proxy \
  --policy demo/fixtures/runtime-policy.yaml \
  --subject finance-analyst \
  --audit demo/output/approval-block.audit.jsonl \
  --alert demo/output/approval-block.alert.jsonl \
  -- "$FAKE_MCP" < "$DEMO_FIXTURES/email-call.jsonl"
printf '\nForward mode (--approval-mode forward):\n'
$CAPLOCK_BIN proxy \
  --policy demo/fixtures/runtime-policy.yaml \
  --subject finance-analyst \
  --approval-mode forward \
  --audit demo/output/approval-forward.audit.jsonl \
  --alert demo/output/approval-forward.alert.jsonl \
  -- "$FAKE_MCP" < "$DEMO_FIXTURES/email-call.jsonl"
printf '\nForward-mode audit record:\n'
python3 -c 'import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2))' < <(tail -n 1 demo/output/approval-forward.audit.jsonl)
COMMAND

record "23-trace-capture" \
  "Capture replayable decisions without leaking arguments" \
  "Execution layer" 0 \
  "Hash-only trace is the default. The audit and trace prove which decisions occurred while the raw email address and body stay out of both files." <<'COMMAND'
$CAPLOCK_BIN proxy \
  --policy demo/fixtures/runtime-policy.yaml \
  --subject finance-analyst \
  --audit demo/output/session.audit.jsonl \
  --trace demo/output/session.trace.jsonl \
  --alert demo/output/session.alert.jsonl \
  -- "$FAKE_MCP" < "$DEMO_FIXTURES/trace-session.jsonl" > demo/output/session.proxy.out
printf 'Audit records:\n'
python3 -c 'import json,sys; [print(json.dumps(json.loads(line), indent=2)) for line in open(sys.argv[1]) if line.strip()]' demo/output/session.audit.jsonl
printf '\nReplayable trace records:\n'
python3 -c 'import json,sys; [print(json.dumps(json.loads(line), indent=2)) for line in open(sys.argv[1]) if line.strip()]' demo/output/session.trace.jsonl
printf '\nRaw argument values present? '
if grep -q 'outside@example.com\|quarterly-secret' demo/output/session.trace.jsonl; then
  echo 'YES'
  exit 1
else
  echo 'no'
fi
COMMAND

record "24-replay-unchanged" \
  "Replay the trace against the same policy" \
  "Execution layer" 0 \
  "Replay uses the same deterministic evaluator as matrix, test, and proxy. The trace is partial because arguments were not captured, and it says so." <<'COMMAND'
$CAPLOCK_BIN replay demo/output/session.trace.jsonl \
  --policy demo/fixtures/runtime-policy.yaml
COMMAND

record "25-replay-weakened" \
  "Catch a weaker policy before it reaches production" \
  "Execution layer" 0 \
  "Replaying historical calls against a permissive policy reveals a weakened approval decision. The CI gates turn that into a non-zero exit." <<'COMMAND'
$CAPLOCK_BIN replay demo/output/session.trace.jsonl \
  --policy demo/fixtures/loose-policy.yaml
printf '\nCI gate results:\n'
if $CAPLOCK_BIN replay demo/output/session.trace.jsonl --policy demo/fixtures/loose-policy.yaml --fail-on-weakened >/dev/null 2>&1; then
  echo 'fail-on-weakened: unexpectedly passed'
  exit 1
else
  echo 'fail-on-weakened: exit 1 (expected)'
fi
if $CAPLOCK_BIN replay demo/output/session.trace.jsonl --policy demo/fixtures/runtime-policy.yaml --strict-args >/dev/null 2>&1; then
  echo 'strict-args: unexpectedly passed'
  exit 1
else
  echo 'strict-args: exit 1 (expected; hash-only trace)'
fi
COMMAND

record "26-replay-strengthened" \
  "Show the opposite direction: a tightened decision" \
  "Execution layer" 0 \
  "A trace captured under the permissive policy is replayed against the stricter runtime policy. The email decision becomes stronger, not weaker." <<'COMMAND'
$CAPLOCK_BIN proxy \
  --policy demo/fixtures/loose-policy.yaml \
  --subject finance-analyst \
  --trace demo/output/loose.trace.jsonl \
  --alert demo/output/loose.alert.jsonl \
  -- "$FAKE_MCP" < "$DEMO_FIXTURES/trace-session.jsonl" >/dev/null
$CAPLOCK_BIN replay demo/output/loose.trace.jsonl \
  --policy demo/fixtures/runtime-policy.yaml
COMMAND

record "27-schema-validation" \
  "Published trace and replay JSON Schemas are executable contracts" \
  "Verification" 0 \
  "The published schemas compile as JSON Schema 2020-12 and are exercised against real writer and render output in the Go test suite." <<'COMMAND'
go test ./internal/trace -run Published -v
python3 -m json.tool schemas/trace.schema.json >/dev/null
python3 -m json.tool schemas/replay.schema.json >/dev/null
printf '\nschemas/trace.schema.json: valid JSON\n'
printf 'schemas/replay.schema.json: valid JSON\n'
COMMAND

record "28-verification" \
  "Run the complete local verification suite" \
  "Verification" 0 \
  "Formatting, vet, shuffled race tests, three cross-platform builds, and optional OPA parity run without network access or deployment." <<'COMMAND'
printf 'gofmt: '
if test -z "$(gofmt -l cmd internal packs demo examples)"; then echo OK; else echo FAILED; exit 1; fi
go vet ./...
go test -shuffle=on -race ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
printf 'cross-builds: windows/amd64 linux/amd64 darwin/arm64: OK\n'
if [ -n "${OPA_BIN:-}" ] && [ -x "$OPA_BIN" ]; then
  make verify-rego OPA_BIN="$OPA_BIN"
elif command -v opa >/dev/null 2>&1; then
  make verify-rego OPA_BIN="$(command -v opa)"
else
  echo 'OPA parity: skipped (set OPA_BIN or install opa)'
fi
COMMAND

record "29-attack-graph" \
  "Search source-to-sink attack paths from the tool inventory" \
  "Evidence layer" 0 \
  "Capabilities from the lockfile infer source, transform, and sink roles. Every path is evaluated by the same policy engine; the graph is a heuristic review aid, not content-level dataflow proof." <<'COMMAND'
go run ./bench/gen -output demo/output/graph.lock
$CAPLOCK_BIN graph examples/policy/caplock.yaml \
  --lockfile demo/output/graph.lock \
  --subject finance-analyst \
  --max-paths 10
printf '\nPermissive-policy gate:\n'
if $CAPLOCK_BIN graph demo/fixtures/loose-policy.yaml \
  --lockfile demo/output/graph.lock \
  --subject finance-analyst \
  --max-paths 10 \
  --fail-on-exposed > demo/output/graph-loose.txt 2>&1; then
  echo 'fail-on-exposed: unexpectedly passed'
  exit 1
fi
printf 'fail-on-exposed: exit 1 (expected); allowed high/critical paths: '
grep -c 'status=allowed' demo/output/graph-loose.txt
COMMAND

record "30-trace-corpus" \
  "Turn observed calls into reviewable regression candidates" \
  "Evidence layer" 0 \
  "Trace-derived expectations capture current behavior, are tagged review-required, and must not be treated as proof of least privilege." <<'COMMAND'
$CAPLOCK_BIN corpus demo/output/session.trace.jsonl \
  --policy demo/fixtures/runtime-policy.yaml \
  -o demo/output/session-candidates.yaml
sed -n '1,44p' demo/output/session-candidates.yaml
printf '\nCandidate corpus executed against the same policy:\n'
$CAPLOCK_BIN test demo/fixtures/runtime-policy.yaml \
  --corpus demo/output/session-candidates.yaml | sed -n '1,10p'
COMMAND

record "31-log-import" \
  "Map a historical CSV log into replayable Caplock traces" \
  "Evidence layer" 0 \
  "The mapping is explicit: missing fields, bad timestamps, and argument-hash mismatches fail closed instead of being guessed." <<'COMMAND'
$CAPLOCK_BIN import "$DEMO_FIXTURES/history.csv" \
  --mapping "$DEMO_FIXTURES/history-mapping.yaml" \
  -o demo/output/imported.trace.jsonl
printf 'Imported trace records:\n'
python3 -c 'import json,sys; [print(json.dumps(json.loads(line), indent=2)) for line in open(sys.argv[1]) if line.strip()]' demo/output/imported.trace.jsonl
printf '\nReplay against the current policy:\n'
$CAPLOCK_BIN replay demo/output/imported.trace.jsonl \
  --policy demo/fixtures/runtime-policy.yaml
COMMAND

record "32-proxy-obligations" \
  "Redact arguments, emit alerts, and enforce a rate limit" \
  "Execution layer" 0 \
  "When a rule carries redact, alert, and rate_limit, the proxy rewrites sensitive fields before forwarding, writes a payload-free alert, and blocks calls over the fixed-window budget." <<'COMMAND'
$CAPLOCK_BIN proxy \
  --policy demo/fixtures/obligation-policy.yaml \
  --subject finance-analyst \
  --audit demo/output/obligation.audit.jsonl \
  --alert demo/output/obligation.alert.jsonl \
  --trace demo/output/obligation.trace.jsonl \
  --trace-arguments full \
  --rate-limit 1/1m \
  -- "$FAKE_MCP" < "$DEMO_FIXTURES/obligation-calls.jsonl" > demo/output/obligation.proxy.out
printf 'Audit records:\n'
python3 -c 'import json,sys; [print(json.dumps(json.loads(line), indent=2)) for line in open(sys.argv[1]) if line.strip()]' demo/output/obligation.audit.jsonl
printf '\nTrace records (redacted full capture):\n'
python3 -c 'import json,sys; [print(json.dumps(json.loads(line), indent=2)) for line in open(sys.argv[1]) if line.strip()]' demo/output/obligation.trace.jsonl
printf '\nAlert records (decisions and hashes only):\n'
python3 -c 'import json,sys; [print(json.dumps(json.loads(line), indent=2)) for line in open(sys.argv[1]) if line.strip()]' demo/output/obligation.alert.jsonl
printf '\nRaw secret values present? '
if grep -Eq 'raw-token|raw-password|second-token|second-password' demo/output/obligation.audit.jsonl demo/output/obligation.trace.jsonl demo/output/obligation.alert.jsonl; then
  echo 'YES'
  exit 1
else
  echo 'no'
fi
COMMAND

record "33-benchmark" \
  "Run the 20-server, 50-case local benchmark" \
  "Verification" 0 \
  "The benchmark generates synthetic MCP servers and exercises graph, matrix, and regression paths without npm, network access, or deployment." <<'COMMAND'
./bench/run.sh
COMMAND

printf '\nCaptured %d scenarios with %d unexpected exit codes.\n' "$scenarios" "$failures"
if ! go run ./demo/cardgen -output demo/output -screenshots demo/screenshots; then
  echo "demo: card generation failed" >&2
  exit 1
fi
if [ "$failures" -ne 0 ]; then
  exit 1
fi
