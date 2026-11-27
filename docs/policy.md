# Policy compilation, evaluation, and lint

`caplock.yaml` is the human-authored policy source. This build provides the
deterministic source loader, Policy IR compiler, lint pass, request evaluator,
regression runner, report renderer, exporter, and reference MCP proxy.

```text
caplock.yaml / policy.json
            │
            ▼
 strict source validation
            │
            ▼
       Policy IR v1 ──► caplock compile
            ├─────────► caplock lint
            ├─────────► caplock test / report
            ├─────────► caplock export
            └─────────► caplock proxy
```

## Workflow

```bash
# Optional: draft from a constrained natural-language brief.
caplock draft policy-brief.txt -o caplock.yaml

# Create a starter policy in the current directory.
caplock init

# Or in another directory. Existing files are not replaced without --force.
caplock init policies --force

# Validate review invariants.
caplock lint caplock.yaml
caplock lint caplock.yaml --strict
caplock lint caplock.yaml --json

# Emit normalized Policy IR.
caplock compile caplock.yaml
caplock compile caplock.yaml --format json
caplock compile caplock.yaml --output policy.ir.json

# Evaluate the deterministic regression corpus and render evidence.
caplock test caplock.yaml
caplock report caplock.yaml --format sarif -o caplock.sarif

# Export or enforce the same IR.
caplock export caplock.yaml --format rego
caplock proxy --policy caplock.yaml --subject finance-analyst -- ./mcp-server
```

`compile` and `lint` default to `caplock.yaml` when no path is supplied. The
compiler accepts YAML or JSON, rejects unknown fields and multiple YAML
documents, and reads at most 1 MiB. It never calls an LLM.

## Source format

```yaml
apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: finance-agent
  owner: security
  description: Least privilege for the finance agent
spec:
  defaults:
    effect: deny
  subjects:
    - id: orchestrator
    - id: finance-analyst
      parent: orchestrator
      delegation: attenuate-only
  rules:
    - id: finance-write-after-hours
      effect: deny
      match:
        capability: [finance.write, finance.approve]
        context:
          time:
            outside: "Mon-Fri 09:00-18:00 Asia/Shanghai"
      obligations: [audit, alert]
    - id: external-to-email
      effect: require_approval
      match:
        sink: email.send
        provenance:
          contains: external_web
      obligations: [human_approval, redact]
```

The full source contract is
[`schemas/policy.schema.json`](../schemas/policy.schema.json). The runnable
example is [`examples/policy`](../examples/policy).

### Required structure

- `apiVersion` must be `caplock/v1alpha1`; `kind` must be `PolicySet`.
- `metadata.name`, `spec.defaults.effect`, and `spec.rules` are required.
  `spec.rules` may be empty but must be present.
- Subject and rule IDs must be non-empty and unique.
- Every rule must select at least one condition.
- Effects are `allow`, `deny`, or `require_approval`.
- Obligations are `audit`, `alert`, `redact`, `human_approval`, or
  `rate_limit`. Unknown obligations are rejected.
- String selector arrays must not contain empty or duplicate values.

### Match selectors

`match` is a conjunction of the fields that are present:

| Field | Meaning |
| --- | --- |
| `subject` | Agent or delegated principal ID |
| `tool` | MCP tool names |
| `capability` | Capability labels from the tool inventory |
| `dataClass` | Data classifications attached to the request |
| `sink` | Destination such as `email.send` |
| `args` | Declarative argument selector with equality and `$exists`, `$regex`, `$prefix`, `$suffix`, `$in`, `$contains`, `$ne` operators |
| `context.time.outside` | Human-readable non-working window evaluated in an IANA time zone |
| `context.environment` | Environment name |
| `context.attributes` | String-valued request attributes |
| `provenance.contains` | Provenance labels carried by the request data |

`provenance.contains` accepts either one string or a string array. The
compiler does not infer missing labels and does not perform DLP or taint
tracking.

### Subjects and delegation

`parent` and `delegation: attenuate-only` express the rule that a child agent may
not exceed its parent's authority. The linter checks for unknown parents,
self-parenting, delegation cycles, and an `attenuate-only` declaration with no
parent. The evidence runner additionally replays delegated corpus cases against
the parent subject and fails when the child decision is weaker than the parent
decision.

### Decision order

The evaluator applies `deny` over `require_approval` over `allow`. Within one
effect, the highest explicit `priority` wins; ties are resolved by source order,
with earlier rules winning. If no rule matches, `spec.defaults.effect` is used.
Every decision carries the matched rules, obligations, source locations, and a
`default` flag so a report can explain the result.

## Evaluation

```go
request := policy.Request{
    Subject:      "finance-analyst",
    Tool:         "email.send",
    Capabilities: []string{"comms", "external", "network"},
    DataClass:    []string{"secret"},
    Sink:         "email.send",
    Args:         map[string]any{"to": "outside@example.com"},
    Provenance:   []string{"external_web"},
    Context: policy.RequestContext{
        Time:        time.Date(2026, 11, 26, 10, 0, 0, 0, shanghai),
        Environment: "production",
        Attributes:  map[string]string{"tenant": "acme"},
    },
}
decision, err := policy.Evaluate(ir, request)
```

The request is caller-supplied. Caplock does not infer provenance, classify the
payload, or perform taint/DLP analysis. The proxy derives capabilities from a
lockfile when one is supplied, otherwise from the deterministic tool-name
heuristic. A zero `Request.Context.Time` uses the current instant; regression
fixtures always set it so results are reproducible.

### Argument selectors

| Selector | Meaning |
| --- | --- |
| `path: value` | Exact JSON value equality |
| `{"$exists": true}` | Key is present |
| `{"$regex": "^/etc/"}` | String matches a RE2 expression |
| `{"$prefix": "/etc/"}` / `{"$suffix": ".pem"}` | String prefix or suffix |
| `{"$in": ["admin", "owner"]}` | Value is in a list |
| `{"$contains": "secret"}` | String contains, or array contains a matching string |
| `{"$ne": value}` | Value is absent or not equal |

Dotted paths such as `request.user.role` are supported. Selectors are validated
at compile time; an invalid operator or regex blocks compilation.

### Time windows

`context.time.outside` accepts `Mon-Fri 09:00-18:00 Asia/Shanghai`. Day ranges,
clock ranges, overnight ranges, and IANA time zones are supported. A rule
matches only when the request time falls outside the named window. Compilation
also normalizes the window for the Rego exporter.

## Policy IR

`caplock compile` emits IR v1. The contract is
[`schemas/ir.schema.json`](../schemas/ir.schema.json).

```json
{
  "irVersion": 1,
  "policy": "finance-agent",
  "defaults": {"effect": "deny"},
  "subjects": [
    {"id": "finance-analyst", "parent": "orchestrator", "delegation": "attenuate-only"},
    {"id": "orchestrator"}
  ],
  "rules": [
    {
      "id": "external-to-email",
      "effect": "require_approval",
      "match": {
        "sink": "email.send",
        "provenance": {"contains": ["external_web"]}
      },
      "obligations": ["human_approval", "redact"],
      "source": {"file": "caplock.yaml", "line": 24, "column": 7}
    }
  ]
}
```

The compiler normalizes subjects and string selector arrays by sorting them.
Rules stay in source order so source-order semantics remain available to the
evaluator. Source locations use the policy file's base name rather than a
machine-specific absolute path. No timestamps are written. Repeated compilation
of the same bytes with the same source name produces byte-identical IR.

`--format ir` emits indented JSON with a trailing newline. `--format json` emits
compact JSON with a trailing newline. The committed example is protected by a
golden test in `internal/policy/policy_test.go`.

## Lint findings

Findings are sorted with errors first, then by source line, code, and message.

| Code | Severity | Meaning |
| --- | --- | --- |
| `default-allow` | warning | Unmatched requests are allowed by default |
| `unknown-parent` | error | A subject references a parent that does not exist |
| `subject-self-parent` | error | A subject names itself as parent |
| `subject-cycle` | error | A delegation cycle exists |
| `orphan-delegation` | warning | `attenuate-only` is declared without a parent |
| `unknown-rule-subject` | error | A rule references an undeclared subject |
| `broad-allow` | warning | An allow rule selects only a subject |
| `wildcard-match` | warning | A tool, capability, or data-class selector is `*` |
| `duplicate-rule` | warning | Multiple rules have identical match selectors |
| `conflicting-effects` | warning | Identical selectors have different effects |

`compile` fails when lint reports an error. Warnings are allowed so the source
can still be compiled for review. `lint` exits with status 1 for errors, and
`lint --strict` also treats warnings as failures.

```console
$ caplock lint caplock.yaml
caplock.yaml:1:1: error [unknown-parent] subject "worker" references unknown parent "missing"
```

JSON output is stable and has this shape:

```json
{
  "version": 1,
  "policy": "finance-agent",
  "issues": []
}
```

## Exit codes

- `0`: policy compiled, or lint found no blocking findings
- `1`: compile-time lint error, or lint findings under `--strict`
- `2`: usage or policy source error
- `3`: internal or filesystem error

## CI

```yaml
- run: go test ./...
- run: go run ./cmd/caplock lint caplock.yaml --strict
- run: go run ./cmd/caplock compile caplock.yaml -o policy.ir.json
```

Commit the generated `policy.ir.json` only when downstream tooling needs a
reviewable artifact. The runtime enforcement surface is intentionally separate
from this policy compilation milestone.

## Current limits

- `caplock draft` is a template compiler for documented statements. It is not
  arbitrary natural-language understanding and does not call an LLM.
- Delegation is checked as an evaluated attenuation invariant over the corpus;
  it is not a formal proof over every possible request.
- A matched decision is only as complete as the policy selectors and the
  request facts supplied by the caller. Provenance and data classes are inputs,
  not DLP or taint-tracking results.
- Trace capture/replay is available, and `caplock corpus` can turn a trace into
  review-required candidates; a human still has to promote them into a security
  gate.
- `caplock graph` provides heuristic source-to-sink discovery, and Cedar/SDK
  export is available. Biscuit remains future work. These layers consume Policy
  IR rather than introducing a second policy format.
