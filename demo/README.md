# Caplock end-to-end demo

This directory is an executable verification suite, not a design mockup. It
runs the real `caplock` binary against checked-in MCP fixtures and writes both
the captured artifacts and the screenshots embedded in the root README.

The demo is deliberately local-only:

- no deployment, upload, publish, or restart;
- no remote MCP server or network access;
- the only child MCP process is `examples/fake-mcp`, built from this repository;
- every output begins as a command, an exit code, and real stdout/stderr.

## Run it

Requirements:

- Go 1.24+ (builds Caplock and the fake MCP server);
- Python 3 (pretty prints JSON artifacts in the trace/SARIF scenarios);
- Node.js plus the Playwright CLI (screenshots only);
- Chrome for Playwright, or set `PLAYWRIGHT_CHANNEL` to another installed
  channel and leave it empty to use Playwright's downloaded browser.

```bash
make build
./demo/run.sh
./demo/screenshots.sh
./demo/verify.sh
```

An OPA binary is optional. It proves Rego parity when available:

```bash
OPA_BIN=/path/to/opa ./demo/run.sh
```

`run.sh` creates `demo/output/` (ignored by Git), one directory per scenario.
Each directory contains `command.txt`, `stdout.txt`, `stderr.txt`,
`exit-code.txt`, `expected-exit.txt`, and `card.html`. A local gallery is at
`demo/output/index.html`.

`screenshots.sh` writes committed PNGs to `demo/screenshots/`.
`verify.sh` checks exit codes, artifacts, privacy invariants, schema tests, and
README references without regenerating anything.

## Scenario coverage

| ID | Layer | What is proven |
| --- | --- | --- |
| `01-overview` | Overview | CLI/version/help surface and all four layers are exposed by one binary. |
| `02-scan-static` | Facts | Static config discovery never executes a server. |
| `03-scan-connected` | Facts | Real `initialize` and paginated `tools/list` capture three tools. |
| `04-lock` | Facts | Deterministic lockfile with hashed manifests and capability labels. |
| `05-diff` | Facts | Tool manifest drift is reviewable and `--exit-code` gates CI. |
| `06-lock-check` | Facts | A stale committed lockfile fails `lock --check`. |
| `07-init` | Intent | Starter policy creation. |
| `08-draft` | Intent | English and Chinese constrained templates compile without an LLM. |
| `09-templates` | Intent | The complete drafting grammar is explicit. |
| `10-lint` | Intent | Drafted and checked-in policies pass strict lint. |
| `11-lint-gate` | Intent | Default-allow warning fails `lint --strict`. |
| `12-compile` | Intent | Deterministic Policy IR with source locations. |
| `13-matrix` | Evidence | Subject-by-tool baseline matrix and conditional-rule visibility. |
| `14-test` | Evidence | All 50 attack-regression cases pass against the finance policy. |
| `15-test-fail` | Evidence | Default-allow exposes 44 high/critical cases and fails. |
| `16-report-text` | Evidence | Blocked, approval-required, allowed paths and blast radius. |
| `17-report-html` | Evidence | Self-contained local HTML report. |
| `18-report-sarif` | Evidence | Policy gaps become SARIF code-scanning results. |
| `19-exports` | Execution | The same IR exports to Rego, Cedar, YAML, JSON, and SDK config. |
| `20-proxy-allow` | Execution | Allowed `tools/call` reaches the child MCP server. |
| `21-proxy-deny` | Execution | Destructive call is blocked before the child sees it. |
| `22-proxy-approval` | Execution | `require_approval` blocks by default and forwards only on explicit opt-in. |
| `23-trace-capture` | Execution | Audit/trace capture retains decisions but not raw arguments. |
| `24-replay-unchanged` | Execution | Same-policy replay reports no changes and marks hash-only input partial. |
| `25-replay-weakened` | Execution | A permissive revision is detected as weakened; CI gates exit 1. |
| `26-replay-strengthened` | Execution | A tightened policy turns recorded allow decisions into stronger decisions. |
| `27-schema-validation` | Verification | Published trace/replay schemas compile and validate real writer/renderer output. |
| `28-verification` | Verification | gofmt, vet, race tests, cross-builds, and optional OPA parity. |
| `29-attack-graph` | Evidence | Source-to-sink paths inferred from 20 tools, evaluated by policy, with a CI gate for exposed paths. |
| `30-trace-corpus` | Evidence | A captured trace becomes review-required regression candidates that execute deterministically. |
| `31-log-import` | Evidence | An explicit CSV mapping imports a historical log and replays it against the current policy. |
| `32-proxy-obligations` | Execution | `redact`, `alert`, and `rate_limit` obligations are enforced at runtime; raw secrets stay out of audit/trace/alert. |
| `33-benchmark` | Verification | The local benchmark runs graph, matrix, and the 50-case corpus over 20 synthetic servers. |

## Fixtures

- `fixtures/runtime-policy.yaml`: default-deny runtime policy with read allow,
  destructive deny, and external-egress approval.
- `fixtures/loose-policy.yaml`: intentionally permissive policy used only to
  demonstrate failed regression, blast radius, and replay weakening.
- `fixtures/zh-security-brief.txt`: supported Chinese drafting statements.
- `fixtures/obligation-policy.yaml` and `fixtures/obligation-calls.jsonl`: runtime redaction, alert, and rate-limit demo.
- `fixtures/history.csv` and `fixtures/history-mapping.yaml`: explicit historical-log import demo.
- `fixtures/*-call.jsonl`: named single-call MCP requests.
- `fixtures/trace-session.jsonl`: two-call session used by trace/replay.

The raw email address and body exist only in the fixture request. The obligation
fixture adds raw token/password values. None may appear in audit, alert, or trace
output; `verify.sh` checks that invariant.
