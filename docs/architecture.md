# Architecture

Caplock is a deterministic pipeline. The current implementation covers the fact
layer, the connected MCP tool surface, policy compilation/lint, request
evaluation, regression evidence, reporting, export, and a reference runtime
proxy. Each layer consumes the same stable inputs rather than re-reading policy
text or provider-specific configuration.

```text
.mcp.json / mcp.json / editor configs
                  │
                  ▼
        config discovery + JSONC
                  │
                  ▼
       normalized server inventory
                  │
                  ├── scan --json
                  ├── explicit --connect ──► tools/list ──► manifest hashes
                  └── caplock.lock ──► diff / CI

policy brief (constrained templates) ──► caplock draft
                  │
                  ▼
caplock.yaml / policy.json
                  │
                  ▼
      strict source validation
                  │
                  ▼
           Policy IR v1
                  ├── compile --format ir ──► reviewable artifact
                  ├── lint ──► errors / review warnings
                  ├── evaluator ──► test / report ──► text / JSON / HTML / SARIF
                  ├── evaluator + lockfile ──► matrix ──► text / JSON / YAML / CSV
                  ├── exporter ──► Rego / Cedar / YAML / JSON / SDK
                  ├── proxy ──► stdio / Streamable HTTP tools/call interception
                  ├── proxy --trace ──► trace JSONL ──► replay / corpus candidates
                  └── lockfile ──► graph ──► source-to-sink candidate paths
```

## Implemented v0.1 layers

- Discover known MCP client config files under a project root.
- Parse `mcpServers` and `servers` entries, including JSONC comments and trailing
  commas.
- Normalize server records and reject malformed entries.
- Redact env/header values before hashing.
- Write a byte-deterministic `caplock.lock`.
- Compare lockfiles by `(source, name)` and semantic content.
- Check committed lockfiles in CI with `lock --check` and `diff --exit-code`.
- Connect to stdio or Streamable HTTP MCP servers only when `--connect` is set.
- Initialize MCP sessions, follow `tools/list` pagination, and enforce message,
  page, tool-count, and timeout limits.
- Store tool description and input-schema hashes without retaining raw input.
- Classify tools into a small capability vocabulary from name, description, and
  annotations.
- Report tool-level additions, removals, and field changes from lockfile diffs.
- Load `caplock/v1alpha1` YAML or JSON with strict unknown-field rejection and a
  1 MiB read limit.
- Compile source into normalized, byte-deterministic Policy IR with rule source
  locations.
- Draft policy YAML from a constrained English/Chinese statement grammar with
  line-level rejection of unknown statements; no LLM is called.
- Lint default-allow, delegation, subject-reference, broad-allow, wildcard,
  duplicate, and conflicting-effect cases.
- Create a starter policy with `caplock init` and compile or lint it from CI.
- Evaluate requests with deny > require_approval > allow precedence, explicit
  priority, source-order tie-breaking, and a default fallback.
- Evaluate tool/capability/sink/dataClass/args/provenance/environment/time
  selectors, including IANA time zones and overnight windows.
- Run a 50-case regression corpus covering prompt injection, secret egress,
  destructive actions, privilege escalation, after-hours finance operations,
  shell execution, tool poisoning, delegation, and unknown tools.
- Check delegation attenuation and tool coverage, and compare decisions against
  a baseline policy.
- Render a baseline subject-by-tool permission matrix from captured tools, with
  conditional candidate rules called out rather than invented facts.
- Render text, JSON, HTML, and SARIF 2.1.0 reports with attack paths, a
  high/critical blast-radius summary, gaps, coverage, and baseline changes.
- Infer bounded source-to-sink attack paths from captured tool capabilities and
  evaluate each sink request against the same policy engine.
- Export Rego, Cedar, YAML, and SDK-neutral JSON/YAML. Cedar rejects selectors
  it cannot represent exactly instead of approximating them.
- Intercept stdio and Streamable HTTP MCP `tools/call` requests, fail closed on
  malformed input, unknown locked tools, evaluator errors, and audit failures,
  and write hash-only JSONL audit records.
- Enforce `audit`, `alert`, `redact`, `rate_limit`, and `human_approval`
  obligations at the reference proxy, failing closed when a required sink or
  runtime budget is absent.
- Optionally capture replayable JSONL traces with argument hashes by default or
  explicit full arguments, then replay recorded decisions against a revised
  policy and classify changed, weakened, and strengthened outcomes.
- Import generic JSONL/CSV historical logs through an explicit mapping, and
  generate review-required corpus candidates from captured traces.
- Publish and test JSON Schemas for trace, replay, attack graph, and import
  mapping in addition to the lockfile, policy, IR, evidence, and report
  contracts.

## Package boundaries

```text
cmd/caplock          process entry point and exit codes
internal/cli         Cobra commands and output formats
internal/config      discovery, JSONC, normalization, redaction
internal/mcp         stdio and Streamable HTTP JSON-RPC transports
internal/manifest    MCP tool normalization and canonical hashing
internal/inventory   deterministic capability classification
internal/lockfile    model, validation, deterministic IO, diff
internal/intent      constrained natural-language template compiler
internal/policy      policy source loader, IR compiler, evaluator, lint, time/args
internal/evidence    corpus loader, regression runner, invariants, coverage, diff
internal/matrix      baseline subject-by-tool permission matrix
internal/trace       strict JSONL trace capture and policy replay
internal/report      text / JSON / HTML / SARIF report builder
internal/exporter    Rego / Cedar / YAML / JSON / SDK renderers
internal/proxy       fail-closed stdio and Streamable HTTP enforcement
internal/version     build-time version
schemas/             public JSON Schema contracts
examples/            runnable fixtures and golden lockfiles / Policy IR
```

`internal/` is not a supported Go API. The public contract is the CLI, the JSON
Schemas, and the documented lockfile and policy behavior.

## Design principles

- **Local-first.** No config, trace, or secret leaves the machine.
- **Deterministic.** Map iteration order never reaches an artifact; no timestamp
  is written. Policy subjects and selector arrays are sorted.
- **Reviewable.** A permission change should be understandable in a plain diff.
- **Static by default.** Parsing a config never executes its command.
- **Explicit execution.** `--connect` is required before any server command is
  run or configured HTTP headers are sent.
- **Fail closed.** Malformed protocol messages, duplicate tools, cursor loops,
  oversized payloads, and missing schemas abort the connected lock. The proxy
  blocks malformed `tools/call`, unknown locked tools, evaluator errors, and
  audit failures.
- **No raw tool prose.** Descriptions and schemas are hashed; only names,
  annotations, and derived capability labels are persisted.
- **Adapters over lock-in.** MCP layouts and protocol versions are normalized at
  the edge.
- **Small dependency surface.** Cobra and `yaml.v3` are the only direct
  dependencies.
- **LLM optional.** No LLM is present in policy compilation, lint, or the CI
  path.
- **Privacy-preserving evidence.** Audit records contain tool names, subjects,
  decisions, rule IDs, capability labels, and an argument hash, never raw
  arguments or tool results. Trace capture is hash-only by default; raw
  arguments require an explicit `--trace-arguments full` opt-in.

## Not implemented yet

- Content-level dataflow proof. The attack graph infers bounded source-to-sink
  candidates from tool capabilities; it does not read tool responses or prove
  that a specific payload reached a specific sink.
- Arbitrary natural-language policy drafting. `caplock draft` supports only the
  documented template grammar; an LLM may later propose candidates, but
  deterministic parsing, lint, and tests remain the trust boundary.
- Full causal audit chains, tool-response capture, Biscuit export, and
  distributed rate limits. Trace replay covers recorded requests and decisions,
  not model reasoning or response data.
- A web dashboard or hosted service.

These are explicit non-goals for this release rather than hidden claims.
