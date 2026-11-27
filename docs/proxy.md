# Runtime proxy

`caplock proxy` is a reference policy enforcement point for MCP `tools/call`.
It evaluates the same compiled policy used by `caplock test` and fails closed by
default. It is deliberately small: it is not a general-purpose gateway, an
identity provider, a DLP engine, or a replacement for a production service mesh.

## stdio

The child MCP server starts only when this command runs.

```bash
caplock proxy \
  --policy caplock.yaml \
  --subject finance-analyst \
  --lockfile caplock.lock \
  --audit caplock-audit.jsonl \
  --alert caplock-alerts.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem ./workspace
```

If any policy rule carries the `audit` obligation, Caplock refuses to start the
proxy without `--audit`. This prevents an unaudited deployment from silently
looking healthy. The audit path must be a regular file, not a symlink or device;
use a dedicated append-only file with restrictive permissions.

The same startup rule applies to `alert` and `rate_limit` obligations:
`--alert` and `--rate-limit` must be present when a rule declares them. For
example:

```bash
caplock proxy \
  --policy caplock.yaml \
  --subject finance-analyst \
  --audit caplock-audit.jsonl \
  --alert caplock-alerts.jsonl \
  --rate-limit 60/1m \
  -- go run ./examples/fake-mcp
```

The proxy reads newline-delimited JSON-RPC from stdin and writes child responses
to stdout. Messages that are not `tools/call` pass through unchanged. Arguments
after `--` are the child command and are never interpreted by a shell.

## Streamable HTTP

```bash
caplock proxy http \
  --policy caplock.yaml \
  --subject finance-analyst \
  --lockfile caplock.lock \
  --audit caplock-audit.jsonl \
  --alert caplock-alerts.jsonl \
  --listen 127.0.0.1:8787 \
  --target http://127.0.0.1:9000
```

The listener defaults to loopback. The proxy intercepts POST JSON-RPC
`tools/call`, preserves MCP session/protocol headers, and passes GET/SSE and
non-`tools/call` requests through to the target. `Mcp-Session-Id`,
`MCP-Protocol-Version`, and other ordinary headers are preserved.

## Decision semantics

| Policy effect | Default proxy behavior | Explicit override |
| --- | --- | --- |
| `allow` | Forward | None |
| `deny` | Block with JSON-RPC error `-32001` | None |
| `require_approval` | Block with JSON-RPC error `-32001` | `--approval-mode forward` |
| No match | Use `spec.defaults.effect` | None |

`--approval-mode forward` is intended for an external approval system. The
request is forwarded and the audit record includes `unenforcedObligations:
["human_approval"]`.

### What is actually enforced

The proxy enforces the policy **effect** and these obligations:

| Obligation | Runtime behavior |
| --- | --- |
| `audit` | Writes a hash-only audit record; a missing or failing sink blocks the call. |
| `alert` | Writes a payload-free alert record; a missing or failing sink blocks the call. |
| `redact` | Recursively replaces matching argument fields before forwarding; audit/trace record paths only. |
| `rate_limit` | Applies a fixed-window budget per subject and tool; exceeding it blocks the call. |
| `human_approval` | Blocked while `require_approval` is in block mode; forwarding is explicit opt-in. |

`--redact-fields` defaults to `password,secret,token,authorization,api_key,access_token,client_secret`.
Entries may be leaf field names or dotted paths such as `nested.password`.
Redaction is case-insensitive and happens before the child MCP server sees the
request.

`--rate-limit` uses `<count>/<duration>`, for example `60/1m` or `10/30s`. The
limiter is in-memory and per proxy process; it is not a distributed quota.

An obligation that the proxy cannot enforce fails closed when the decision would
otherwise be forwarded. The call is marked `runtimeBlocked` when the failure is
runtime-specific (missing alert sink, missing limiter, or exceeded budget).

## Capability resolution

For each `tools/call`, the proxy builds a `policy.Request` with:

- `subject`: `--subject`
- `tool`: `params.name`
- `args`: `params.arguments`
- `sink`: conservative classifier such as `email.send` or `shell.exec`
- `context.time`: current time
- `context.environment`: `--environment`

Capabilities come from:

1. The lockfile entry for the tool, unioned across servers if the same tool name
   appears more than once.
2. The deterministic tool-name heuristic when no lockfile is supplied.
3. The heuristic when the lockfile has no captured tool manifests.

If the lockfile contains captured tools and the tool is absent, the proxy denies
before evaluating the policy. This treats manifest drift as a security event.
Pass a connected lockfile (`caplock lock --connect`) to get this behavior.

## Fail-closed cases

The proxy blocks and does not forward when:

- the JSON-RPC envelope is invalid for `tools/call`
- `params.arguments` is not an object
- the tool is absent from a populated lockfile
- policy evaluation returns an error
- the audit or trace sink cannot be written
- a message exceeds the configured size limit
- a batch JSON-RPC request is received

Malformed JSON, invalid params, and batch requests are rejected instead of being
forwarded, because the proxy cannot prove that they are not a bypass attempt.

## Audit records

`--audit` enables append-only JSONL. The file is created with owner-only
permissions. Each record contains:

```json
{
  "version": 1,
  "time": "2026-11-26T06:59:02.055696Z",
  "policy": "finance-agent",
  "subject": "finance-analyst",
  "tool": "send_email",
  "effect": "deny",
  "ruleId": "",
  "default": true,
  "obligations": [],
  "capabilities": ["comms"],
  "capabilitySource": "heuristic",
  "sink": "email.send",
  "argsHash": "sha256:...",
  "redactedFields": ["token"],
  "runtimeBlocked": false,
  "forwarded": false,
  "reason": "denied by the default policy",
  "approvalMode": "block"
}
```

Raw arguments, headers, tool results, and child stderr are never recorded in the
audit log. `argsHash` is a SHA-256 of canonical JSON and is useful for
correlation without retaining payloads.

Alert records contain the decision, rule, capabilities, sink, reason, and
argument hash. They do not contain raw arguments.

## Replayable traces

`--trace <path>` writes a separate JSONL trace for `caplock replay`. It uses the
same fail-closed behavior as the audit sink. Argument capture defaults to
`--trace-arguments hash`; use `--trace-arguments full` only when the trace file
is protected and retention is approved.

```bash
caplock proxy \
  --policy caplock.yaml \
  --subject finance-analyst \
  --trace caplock-trace.jsonl \
  --alert caplock-alerts.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem ./workspace

caplock replay caplock-trace.jsonl --policy caplock.yaml --fail-on-weakened
```

See [trace capture and replay](trace.md) for the record format and imported-log
mapping.

## Error shape

Blocked calls return a JSON-RPC error:

```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "error": {
    "code": -32001,
    "message": "caplock: denied by policy rule \"deny-destructive\"",
    "data": {
      "caplock": {
        "effect": "deny",
        "ruleId": "deny-destructive",
        "default": false,
        "reason": "denied by policy rule \"deny-destructive\"",
        "unenforcedObligations": []
      }
    }
  }
}
```

The error intentionally contains no arguments or upstream response body.

## HTTP status behavior

| Situation | Status |
| --- | --- |
| Allowed call / non-`tools/call` | Upstream response |
| Policy block | `200` with JSON-RPC error |
| Invalid JSON, batch, invalid params | `400` with JSON-RPC error |
| Body too large | `413` with JSON-RPC error |
| Audit or trace unavailable | `503` with JSON-RPC error |
| Upstream unavailable | `502` with sanitized JSON-RPC error |

## Limits

- stdio request frame: 8 MiB
- stdio child response frame: 64 MiB
- HTTP request body: 8 MiB
- HTTP header bytes: 1 MiB
- HTTP read-header timeout: 10 seconds
- HTTP idle timeout: 2 minutes

## Runtime inspection

The audit sink is the source of truth for what happened. Useful fields:

- `forwarded: false` plus `runtimeBlocked: true` means the policy allowed the
  call but a runtime obligation stopped it.
- `redactedFields` lists the argument paths rewritten before forwarding.
- `unenforcedObligations` is non-empty only when the proxy could not enforce a
  declared obligation; such a forwardable decision is blocked.
- `argsHash` correlates repeated calls without retaining payloads.

## Limitations

- No batch JSON-RPC support. Batches are rejected.
- No tool-result inspection, response redaction, or multi-step taint tracking.
- No approval UI, distributed rate-limit store, or alert routing beyond JSONL.
- Trace replay covers recorded requests and decisions, not tool responses or
  multi-step model reasoning.
- Duplicate tool names across servers are unioned; the proxy does not know which
  server an incoming call targets unless the transport routing provides it.
- HTTP GET/SSE is passed through; policy is enforced on POST `tools/call` only.
