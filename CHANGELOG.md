# Changelog

All notable changes to this project will be documented here.

## 0.1.0 - 2026-11-27

First public capability release.

### Added

- Go implementation of the `caplock` CLI with `scan`, `lock`, `diff`, `init`,
  `draft`, `compile`, `lint`, `matrix`, `graph`, `test`, `report`, `corpus`,
  `import`, `export`, `replay`, `proxy`, and `version`.
- Static MCP config discovery for `.mcp.json`, `mcp.json`, `mcp_config.json`,
  editor configs, and Claude Desktop configs.
- JSONC comments and trailing comma support with fuzz coverage.
- Deterministic `caplock.lock` v1, redacted env/header values, canonical config
  hashes, and a reserved optional `tools` array.
- `lock --check`, `diff --exit-code`, JSON output, stable exit codes, and golden
  tests.
- Lockfile, policy, Policy IR, evidence, report, trace, replay, attack-graph,
  and import-mapping JSON Schemas.
- Go CI, lint configuration, and a composite GitHub Action.
- Apache-2.0 license and community files.
- Explicit `--connect` mode for stdio and Streamable HTTP MCP servers.
- MCP `initialize` and paginated `tools/list` support with session handling,
  per-server timeouts, and protocol message limits.
- Tool manifest hashes for descriptions and canonicalized input schemas.
- Deterministic capability classification from tool names, descriptions, and
  MCP annotations.
- Tool-level lockfile diffs with added, removed, and changed tool details.
- `caplock init` for creating a starter `caplock/v1alpha1` policy set.
- Constrained English/Chinese natural-language `draft` compiler with explicit
  templates, line-level diagnostics, optional `@template` selection, delegation
  attenuation subjects, and automatic validation of generated YAML.
- Strict YAML/JSON policy loading with unknown-field rejection, a 1 MiB source
  cap, and single-document enforcement.
- Deterministic Policy IR v1 compilation with preserved rule source locations,
  normalized selector ordering, and golden coverage for the bundled example.
- `caplock compile --format ir|json` and `--output` for reviewable policy
  artifacts.
- Deterministic policy lint for default-allow, delegation errors, broad allows,
  wildcards, duplicate rules, conflicting effects, shadowed rules, and empty
  matches.
- `caplock lint --strict` and `--json`, plus policy-source fuzz coverage.
- Policy compilation/lint documentation and a runnable source-to-IR example.
- Deterministic policy evaluator with `deny > require_approval > allow`
  precedence, explicit priority, source-order ties, matched-rule traces, and a
  default fallback.
- Argument selectors (`$exists`, `$regex`, `$prefix`, `$suffix`, `$in`,
  `$contains`, `$ne`), provenance, environment, data-class, sink, and IANA
  time-window evaluation including overnight windows.
- Strict evidence corpus loader, embedded 50-case MCP attack baseline, delegation
  attenuation invariant, tool-coverage check, and baseline decision diff.
- `caplock test` with text/JSON output, `--corpus`, `--baseline`, `--lockfile`,
  `--allow-failures`, and `--fail-on-baseline-change`.
- `caplock graph` with heuristic source/intermediate/sink inference, bounded
  direct and one-intermediate path search, deterministic policy evaluation,
  text/JSON/YAML output, `--max-paths`, and `--fail-on-exposed`.
- `caplock report` with text, JSON, HTML, and SARIF 2.1.0 output, policy gaps,
  attack paths, high/critical blast-radius summaries, coverage, and baseline
  changes.
- `caplock matrix` for deterministic subject-by-tool baseline decisions over a
  captured lockfile, with conditional candidate rules and text/JSON/YAML/CSV
  output.
- `caplock export` for Rego, Cedar, YAML, JSON, and SDK-neutral config. Cedar
  rejects unsupported time windows and non-equality selectors rather than
  approximating them.
- OPA-valid Rego export fixes (reserved `input` bindings, non-recursive argument
  lookup, and explicit default-decision branches) plus an optional `opa eval`
  parity suite runnable with `make verify-rego`.
- Fail-closed stdio proxy and Streamable HTTP proxy for MCP `tools/call`, with
  lockfile drift checks, approval-mode handling, hash-only JSONL audit, message
  limits, batch rejection, and sanitized errors.
- Runtime obligation enforcement for `alert`, `redact`, and `rate_limit` in
  addition to `audit` and `human_approval`; missing sinks or budgets fail closed
  and are recorded as `runtimeBlocked`.
- Recursive, case-insensitive argument redaction by leaf name or dotted path,
  applied before forwarding and recorded as field paths only.
- Replayable JSONL traces from both proxy transports, argument hashes by
  default, explicit full-argument capture, `--trace-redact`, strict trace
  parsing, argsHash verification, and `caplock replay` with changed/weakened/
  strengthened decisions, `argsMissing`, `argsRedacted`, and CI gates.
- `caplock corpus` for review-required regression candidates generated from a
  captured trace.
- `caplock import` for generic JSONL/CSV historical logs with an explicit
  mapping, strict timestamps, required fields, and argument-hash validation.
- Published `trace.schema.json` and `replay.schema.json` with tests against the
  real writer and renderer output, including rejection of unknown fields.
- Reproducible 33-scenario local demo with committed screenshots for discovery,
  locking, drafting, lint gates, Policy IR, matrix, the 50-case corpus, attack
  graph, trace-generated corpus, historical-log import, reports, exports, proxy
  decisions, runtime obligations, trace privacy, replay direction, schema
  validation, benchmark, and the full verification suite.
- Local benchmark harness with 20 synthetic MCP servers, graph search, matrix
  rendering, and the 50-case regression corpus, with a deterministic graph and
  corpus baseline in `bench/baseline.txt`.
- Release engineering configuration: Dockerfile, GoReleaser, checksums, SBOM,
  and a GitHub release workflow. No artifact has been published.
- Repository release-contract tests for the module/install path, composite
  Action, issue links, GoReleaser build/archive/checksum/SBOM settings, release
  tag workflow, and Dockerfile stages/static build.
- Local release dry-run, clean-room reproduction, and fail-closed security
  negative suites, exposed as `make release-dry-run`, `make clean-room`, and
  `make security-negative`.
- Linux CI e2e coverage for the release contract, bounded graph/import smoke
  tests, security negative checks, all 33 demo scenarios, demo verification,
  and the deterministic benchmark baseline.
- A 10-minute local quickstart and an explicit limits section covering the
  heuristic graph, bounded drafting, trace/audit boundaries, missing Biscuit
  support, unimplemented code-scanning upload, and excluded SaaS features.
- Public security and conduct contact email for reports that cannot use GitHub's
  private advisory flow.
- Detailed inventory sub-capabilities (`finance.write`, `finance.approve`,
  `identity.write`, `external.read`) and conservative sink classification.
- Compile, evaluate, evidence, report, exporter, proxy, and CLI coverage,
  including race, fuzz, cross-platform build, and HTML escaping tests.
