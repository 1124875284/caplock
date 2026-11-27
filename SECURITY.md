# Security Policy

## Reporting a vulnerability

Please do not open a public issue. Use GitHub's private vulnerability reporting:

<https://github.com/1124875284/caplock/security/advisories/new>

If GitHub private reporting is unavailable, email
[qq1124875284@163.com](mailto:qq1124875284@163.com).

Include the affected version, a minimal reproduction, impact, and whether secrets
could be exposed.

## Scope

Caplock reads MCP configs and can explicitly connect to MCP servers to read
their tool manifests. It also parses local policy source into Policy IR. We care
about:

- secret leakage through lockfiles, logs, errors, or reports
- path traversal and unsafe file handling
- lockfile integrity and deterministic hashing
- CI action command injection
- dependency supply chain
- command execution and remote requests in connected mode
- MCP response parsing, resource exhaustion, and tool-manifest integrity
- policy parser confusion, unbounded input, source-location leakage, and lint
  bypasses
- policy evaluation errors, selector confusion, time-window mistakes, and
  regression false negatives
- proxy bypass, request smuggling, JSON-RPC batch/framing confusion, audit
  tampering or leakage, and fail-open behavior

## Design commitments

- Local-first: no config, trace, or secret leaves the machine by default.
- Env and header values are never written to the lockfile.
- The lockfile contains a redacted config hash, not raw credentials.
- Connected mode is opt-in through `--connect`; static discovery never starts a
  configured command or opens a network connection.
- Connected mode passes env/header values only to the selected server and does
  not echo server stderr, HTTP response bodies, or raw tool descriptions.
- Tool descriptions and input schemas are hashed before writing; only names,
  annotation hints, and derived capabilities are persisted.
- MCP messages, pages, tools, configs, and lockfiles have hard size/count limits.
- Policy source is read through the same bounded regular-file reader, capped at
  1 MiB. Unknown fields and multiple YAML documents are rejected.
- Policy compilation and lint are deterministic and never call an LLM or network
  service.
- Policy evaluation is deterministic. Regression corpora always carry explicit
  request times; a zero request time uses the current instant.
- The stdio and HTTP proxies fail closed on malformed `tools/call` payloads,
  unknown tools when a populated lockfile is supplied, evaluator errors, and
  audit write failures. A decision requiring `audit` is also blocked when no
  `--audit` sink is configured.
- `require_approval` is blocked by default. `--approval-mode forward` is an
  explicit opt-in that records the unenforced `human_approval` obligation in the
  audit log.
- Proxy audit is JSONL on an explicit `--audit` path with owner-only creation.
  It records subject, tool, effect, rule ID, capability labels, and a SHA-256
  argument hash; it never records raw arguments, headers, or tool results.
- Child MCP stderr is discarded by default. `--child-stderr inherit` is an
  explicit debugging opt-in because child output may contain sensitive data.
- The HTTP proxy only intercepts POST JSON-RPC `tools/call`. GET/SSE and
  non-`tools/call` requests pass through; MCP session and protocol headers are
  preserved. Batch JSON-RPC is rejected rather than partially evaluated.
- Rego export is structurally tested but is not claimed to be OPA-verified until
  an integration test runs a real OPA evaluator in CI.
- Human-readable output escapes terminal control characters so repository names
  cannot inject ANSI sequences into logs.
- Config and lockfile reads are bounded to 16 MiB and require a regular file.
- Releases will be signed and accompanied by an SBOM once publishing starts.
