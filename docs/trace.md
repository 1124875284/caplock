# Trace capture and replay

Caplock can record evaluated MCP tool calls and replay them against a later
policy revision. This is the feedback loop that a static policy review cannot
provide:

> Before this policy change, what did the agent actually do, and which recorded
> decisions would now change?

The replay uses the same deterministic evaluator as `caplock test`,
`caplock matrix`, and `caplock proxy`. No LLM or network call is involved.

## Capture with the proxy

Add `--trace` to either proxy transport:

```bash
caplock proxy \
  --policy caplock.yaml \
  --subject finance-analyst \
  --lockfile caplock.lock \
  --audit caplock-audit.jsonl \
  --alert caplock-alerts.jsonl \
  --trace caplock-trace.jsonl \
  -- npx -y @modelcontextprotocol/server-filesystem ./workspace
```

The trace file is append-only JSONL and is created with owner-only permissions.
Trace write failures block the request, matching the fail-closed behavior of the
audit sink.

By default only an argument hash is recorded:

```bash
--trace-arguments hash
```

To replay argument selectors precisely, explicitly capture full arguments:

```bash
--trace-arguments full
```

`full` records raw tool arguments. Treat the trace file as sensitive, restrict
its retention, and prefer a local/private filesystem. Caplock prints a warning
on stderr when this mode is enabled.

Redact sensitive fields from full capture without changing the forwarded
request:

```bash
caplock proxy \
  --policy caplock.yaml \
  --subject finance-analyst \
  --audit caplock-audit.jsonl \
  --alert caplock-alerts.jsonl \
  --trace caplock-trace.jsonl \
  --trace-arguments full \
  --trace-redact token,nested.password \
  -- npx -y @modelcontextprotocol/server-filesystem ./workspace
```

Field names are matched case-insensitively at every depth, and dotted paths are
supported. A rule carrying the `redact` obligation also redacts the fields
configured by `--redact-fields` from full trace capture. The trace records the
redacted paths in `redactedFields`; values never appear.

## Replay

```bash
caplock replay caplock-trace.jsonl --policy caplock.yaml
caplock replay caplock-trace.jsonl --policy caplock.yaml --format json -o replay.json
```

The text report shows:

- trace and policy identity
- total, unchanged, changed, weakened, strengthened, `args_missing`, and
  `args_redacted` counts
- each changed call with its before/after effect, rule, default status, and
  obligations

Example:

```text
Caplock trace replay
Source: caplock-trace.jsonl
Policy: replay-check
Records: total=2 unchanged=0 changed=2 weakened=1 strengthened=1 args_missing=2 args_redacted=0

Changes:
  [STRENGTHENED] 2026-11-26T07:49:55Z read_file subject=finance-analyst args_captured=false
    before: allow rule=allow-read-only-tools default=false obligations=[]
    after:  deny rule=(default) default=true obligations=[]
  [WEAKENED] 2026-11-26T07:49:55Z send_email subject=finance-analyst args_captured=false
    before: deny rule=(default) default=true obligations=[]
    after:  allow rule=allow-comms default=false obligations=[]
```

`weakened` means the new effect is lower in the order `deny` >
`require_approval` > `allow`. A rule or obligation change without an effect
change is reported as `changed`.

When a trace contains captured arguments and `redactedFields` is empty, replay
re-verifies `argsHash` against `args` and rejects a mismatch by default. A
redacted trace cannot prove the original argument values, so replay marks it as
`args_redacted` and treats it as a partial replay. `--allow-args-hash-mismatch`
exists only for reviewed imports where an upstream pipeline changed the payload
representation without changing intent.

## CI gates

```bash
# Any decision change blocks the PR.
caplock replay caplock-trace.jsonl --policy caplock.yaml --fail-on-change

# Only a weaker decision blocks the PR.
caplock replay caplock-trace.jsonl --policy caplock.yaml --fail-on-weakened

# Refuse a partial replay when the trace was hash-only.
caplock replay caplock-trace.jsonl --policy caplock.yaml --strict-args
```

Exit codes:

- `0`: replay completed and the selected gate passed
- `1`: a requested gate failed
- `2`: policy, trace, format, or usage error
- `3`: output write error

## Trace record

Each line is a strict JSON object. Unknown fields are rejected. The file is
capped at 16 MiB and 10,000 records.

```json
{
  "version": 1,
  "time": "2026-11-26T07:49:50.203045Z",
  "policy": "finance-agent",
  "subject": "finance-analyst",
  "tool": "read_file",
  "capabilities": ["read"],
  "capabilitySource": "heuristic",
  "sink": "file.read",
  "argumentsCaptured": false,
  "argsHash": "sha256:...",
  "redactedFields": [],
  "decision": {
    "effect": "allow",
    "ruleId": "allow-read-only-tools",
    "default": false,
    "obligations": [],
    "forwarded": true,
    "approvalMode": "block"
  }
}
```

When `argumentsCaptured` is true, an `args` object is present. Optional
`environment`, `dataClass`, `provenance`, and `servers` fields let imported
historical logs replay richer selectors.

`redactedFields` is present only when full capture redacted one or more paths.
It requires `argumentsCaptured: true` and the original `argsHash`, but the
recorded `args` are not a hash preimage and must not be treated as the original
payload.

### Published JSON Schema

The per-line record contract is published at
[`schemas/trace.schema.json`](../schemas/trace.schema.json). It uses JSON Schema
2020-12, rejects unknown fields, and permits `args` only when
`argumentsCaptured` is true. A JSONL file is not a JSON array: validate each
non-blank line independently.

## Historical logs

Caplock does not require the proxy to produce the trace. Any log pipeline can
emit this JSONL shape, or map a vendor export explicitly:

```bash
caplock import history.csv \
  --mapping history-mapping.yaml \
  -o caplock-trace.jsonl
caplock replay caplock-trace.jsonl --policy caplock.yaml
```

The mapping is strict YAML or JSON. It names the source field for every required
fact and supports JSONL and CSV input. Missing fields, unknown formats, bad
timestamps, and argument-hash mismatches fail closed; Caplock does not guess
vendor-specific column names.

```yaml
version: 1
inputFormat: csv
fields:
  time: time
  policy: policy
  subject: subject
  tool: tool
  capabilities: capabilities
  decision.effect: effect
  decision.ruleId: ruleId
  sink: sink
  provenance: provenance
```

For a historical call log, map at minimum:

- timestamp to `time` (RFC3339)
- agent identity to `subject`
- tool name to `tool`
- recorded policy effect/rule to `decision.effect` and `decision.ruleId`
- capability labels to `capabilities`
- argument hash to `argsHash`

Add `argumentsCaptured: true` and `args` only when your data policy permits
retaining the payload. Without arguments, replay still checks capability, sink,
time, environment, provenance, and data-class selectors, but the report marks
the run as partial with `args_missing`.

## Published replay schema

The machine-readable replay report contract is published at
[`schemas/replay.schema.json`](../schemas/replay.schema.json). It validates the
output of:

```bash
caplock replay caplock-trace.jsonl \
  --policy caplock.yaml \
  --format json \
  -o replay.json
```

The schema covers the summary counts, `argsMissing`, and each before/after
decision change. It is tested against `trace.Render` output, not a hand-written
report. See [Published JSON Schemas](schemas.md) for validation examples and
versioning rules.

## Limitations

- The proxy captures requests and decisions, not tool responses or multi-step
  model reasoning. It is not a full causal audit chain.
- The proxy does not infer provenance or data classes. Imported logs may supply
  them, but Caplock does not perform DLP or taint tracking.
- `argsHash` is re-verified when unredacted arguments are captured. Redacted or
  hash-only traces remain partial and cannot prove argument-dependent decisions.
- Hash-only traces cannot prove argument-dependent decisions. Use
  `--strict-args` when that precision is required.
- Trace files contain raw arguments only in explicit `full` mode. Use
  `--trace-redact` or a `redact` obligation to remove sensitive fields.

## Generate a regression corpus from a trace

Observed calls can seed a reviewable evidence corpus:

```bash
caplock corpus caplock-trace.jsonl \
  --policy caplock.yaml \
  -o candidates.yaml
caplock test caplock.yaml --corpus candidates.yaml
```

Each case records the current policy decision and is tagged
`trace-generated, review-required`. This is a change-detection aid, not proof
that the observed behavior is least privilege. Redacted or missing arguments
produce slightly weaker candidates rather than guessed values.
