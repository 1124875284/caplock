# Export backends

`caplock export` renders compiled Policy IR for another runtime. The source of
truth remains `caplock.yaml`; exports are generated artifacts and should not be
edited by hand.

```bash
caplock export caplock.yaml --format rego -o policy.rego
caplock export caplock.yaml --format cedar -o policy.cedar
caplock export caplock.yaml --format yaml -o policy.export.yaml
caplock export caplock.yaml --format json -o policy.export.json
caplock export caplock.yaml --format sdk -o policy.sdk.json
```

The default format is `rego`.

## Formats

| Format | Use |
| --- | --- |
| `rego` | OPA/Open Policy Agent evaluation |
| `cedar` | Cedar authorization policies, restricted to the representable subset |
| `yaml` | SDK configuration or reviewable normalized policy |
| `json`, `sdk` | SDK configuration or machine processing |

All formats are deterministic for the same Policy IR. Exports are blocked when
the policy has lint errors.

## Rego input contract

The generated module expects a JSON input object:

```json
{
  "subject": "finance-analyst",
  "tool": "send_email",
  "capabilities": ["comms", "external", "network"],
  "dataClass": ["secret"],
  "sink": "email.send",
  "args": {"to": "outside@example.com"},
  "provenance": ["external_web"],
  "context": {
    "environment": "production",
    "attributes": {"tenant": "acme"},
    "weekday": 4,
    "minute": 600
  }
}
```

`context.weekday` uses `0=Sunday`, and `context.minute` is the local wall-clock
minute in the time zone compiled into the time-window rule. The exporter
normalizes a human window such as
`Mon-Fri 09:00-18:00 Asia/Shanghai` into `days`, `startMinute`, `endMinute`, and
`timezone` fields.

The result is:

```json
{
  "effect": "require_approval",
  "ruleId": "approve-external-provenance-egress",
  "default": false,
  "obligations": ["audit", "human_approval", "redact"]
}
```

The module applies the same semantics as the Go evaluator:

1. `deny` > `require_approval` > `allow`
2. highest explicit `priority` within the selected effect
3. earliest source-order rule on a priority tie
4. `defaults.effect` when no rule matches

## Validation status

Rego rendering has structural and determinism tests in the Go test suite. The
optional parity test also runs generated Rego through a real `opa eval` and
compares effect, rule, default status, and obligations with the Go evaluator:

```bash
make verify-rego OPA_BIN=/path/to/opa
```

The parity test matrix covers default deny, allow, deny, approval, time-window,
argument selectors, provenance, and sink matching. The test skips when OPA is
not installed, so the default Go test suite does not make OPA a build
dependency. Run `make verify-rego` in release checks when OPA is available.

## YAML and JSON

`yaml` and `json` emit the normalized SDK-neutral document:

```json
{
  "version": 1,
  "policy": "finance-agent",
  "defaults": {"effect": "deny"},
  "subjects": [],
  "rules": []
}
```

YAML omits rule `source` locations because `policy.Rule` marks that field
`yaml:"-"`. JSON and Rego retain source locations for traceability. Subjects and
string selector arrays are normalized by the compiler.

## Cedar

Cedar has no `require_approval` primitive, so both `deny` and
`require_approval` rules are exported as `forbid`. This is deliberately
conservative: a Cedar consumer cannot silently reinterpret an approval gate as
an allow.

The exporter rejects anything it cannot represent exactly, including time
windows and non-equality argument operators. It does not approximate them.

```cedar
// require_approval is exported as forbid because Cedar has no approval primitive.
forbid (principal, action, resource) when {
  (context.capabilities.contains("comms") || context.capabilities.contains("external"))
};
```

Use a policy composed only of capability, subject, sink, data-class, and scalar
equality selectors when Cedar is the target. The bundled
`demo/fixtures/runtime-policy.yaml` is a working example.

## SDK config

`sdk` is the normalized document consumed by an SDK or proxy adapter. It is
identical to `json` today and includes subjects, defaults, rules, obligations,
and source locations. It does not generate language-specific code.
