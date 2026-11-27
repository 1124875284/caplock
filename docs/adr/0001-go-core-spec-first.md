# ADR 0001: Go core, spec-first, deterministic CI

- Status: Accepted
- Date: 2026-11-26

## Context

Caplock must discover MCP capability surfaces, produce reviewable artifacts, and
run in CI without executing untrusted MCP servers by default. The project is
open source and should remain a single, auditable binary with a small dependency
surface. The public contract needs to outlive any particular implementation.

## Decision

1. **Go core.** Caplock ships as one static binary built with a currently
   supported Go toolchain. Cobra and `yaml.v3` are the only direct dependencies.
2. **Spec-first.** JSON Schema in `schemas/` is the public contract. Go packages
   under `internal/` are implementation details and may change between releases.
3. **Static by default.** `scan` parses configuration but never executes a
   configured command. Connected mode is available only through the explicit
   `--connect` flag.
4. **Deterministic artifacts.** Lockfiles contain no timestamps or absolute
   paths. Servers, key names, tools, and capabilities are sorted. Secret values
   are redacted before hashing and are never serialized.
5. **No LLM in the trust path.** Policy evaluation, regression tests, and CI do
   not call an LLM. `draft` is a constrained deterministic template compiler; a
   future `explain` or optional LLM assistant may propose candidates, but
   deterministic parsing and human review remain mandatory.
6. **Reference proxy, not a production gateway.** The v0.1 proxy proves that the
   same IR can enforce `tools/call` for stdio and Streamable HTTP. High
   availability, multi-tenancy, and a control plane are explicitly out of scope.
7. **Adapters at the edges.** MCP configuration layouts and protocol versions are
   normalized before they reach the core so ecosystem churn does not reshape the
   lockfile or IR.
8. **Small JSONC implementation.** Editor configs may contain comments and
   trailing commas. The parser is local, fuzzed, and does not pull in a library
   whose toolchain requirements can raise Caplock's minimum Go version.

## Consequences

- Contributors can run the full CI path with `go test ./...` and no cloud
  services, API keys, or LLM access.
- The JSON Schemas must be versioned and treated as carefully as code.
- Lockfile v1 already reserves an optional `tools` array so tool manifests do not
  require a format migration.
- Static scans cannot detect a server that lies about its tools. That requires
  the explicit connected mode.
- The proxy is a reference enforcement point with hash-only audit; it is not a
  sandbox or a full DLP/gateway product.
- Policy compilation, lint, and evaluation are deterministic. The evaluator is a
  library and a CLI/proxy input; it is not a proof system and does not infer
  provenance or perform DLP.
- Rego, Cedar, and Biscuit are export targets, not core dependencies.
