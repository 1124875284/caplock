# Published JSON Schemas

Caplock publishes machine-readable contracts under [`schemas/`](../schemas).
They use JSON Schema draft 2020-12 and are exercised by Go tests against the
actual writer and renderer output, not a hand-written fixture alone.

| Artifact | Schema | Canonical `$id` |
| --- | --- | --- |
| MCP capability lockfile | [`caplock.lock.schema.json`](../schemas/caplock.lock.schema.json) | `https://caplock.dev/schemas/caplock.lock.schema.json` |
| Policy source (`caplock.yaml`) | [`policy.schema.json`](../schemas/policy.schema.json) | `https://caplock.dev/schemas/policy.schema.json` |
| Compiled Policy IR | [`ir.schema.json`](../schemas/ir.schema.json) | `https://caplock.dev/schemas/ir.schema.json` |
| Evidence corpus | [`evidence.schema.json`](../schemas/evidence.schema.json) | `https://caplock.dev/schemas/evidence.schema.json` |
| Text/JSON/HTML/SARIF report model | [`report.schema.json`](../schemas/report.schema.json) | `https://caplock.dev/schemas/report.schema.json` |
| Trace JSONL record | [`trace.schema.json`](../schemas/trace.schema.json) | `https://caplock.dev/schemas/trace.schema.json` |
| Trace replay JSON report | [`replay.schema.json`](../schemas/replay.schema.json) | `https://caplock.dev/schemas/replay.schema.json` |
| Attack graph JSON report | [`attackgraph.schema.json`](../schemas/attackgraph.schema.json) | `https://caplock.dev/schemas/attackgraph.schema.json` |
| Historical log import mapping | [`import-mapping.schema.json`](../schemas/import-mapping.schema.json) | `https://caplock.dev/schemas/import-mapping.schema.json` |

The canonical IDs identify the contracts. The checked-in files under
`schemas/` are the source of truth; the project does not require a hosted schema
registry to validate an artifact.

## Trace record

[`trace.schema.json`](../schemas/trace.schema.json) validates **one line** of
the newline-delimited JSON trace produced by `proxy --trace` or imported from a
compatible historical log pipeline. A JSONL file is not a JSON array: validate
each non-blank line against the schema.

The record is strict. Unknown fields are rejected (`additionalProperties:
false`), and `args` is only legal when `argumentsCaptured` is true. Caplock also
enforces limits not expressible in a standalone record schema:

- at most 16 MiB per trace file;
- at most 10,000 records;
- one JSON value per line;
- SHA-256 argument hashes use the `sha256:<64 lowercase hex>` form;
- trace write failure blocks the proxied request.

The default proxy mode records `argsHash` only. `--trace-arguments full` adds a
raw `args` object and must be treated as sensitive data. `--trace-redact`
removes selected fields and records their paths in `redactedFields`; a redacted
record keeps the original `argsHash` but is treated as a partial replay.

## Replay report

[`replay.schema.json`](../schemas/replay.schema.json) validates the output of:

```bash
caplock replay TRACE --policy caplock.yaml --format json -o replay.json
```

The report contains counts plus an array of changed decisions. Each change
carries the before/after effect, rule ID, default flag, and obligations, with a
direction of `weakened`, `strengthened`, or `changed`. Hash-only trace records
are represented by `argumentsCaptured: false` and counted in `argsMissing`;
redacted records are counted in `argsRedacted`. The schema does not pretend that
missing or redacted arguments were evaluated.

## Attack graph report

[`attackgraph.schema.json`](../schemas/attackgraph.schema.json) validates
`caplock graph --format json`. Every path carries its source labels, steps,
status, policy decision, and `argumentDependent` marker. The schema describes
the report shape; it does not turn the heuristic graph into content-level
dataflow proof.

## Historical log mapping

[`import-mapping.schema.json`](../schemas/import-mapping.schema.json) validates
the strict mapping consumed by `caplock import`. Required facts are named
explicitly; optional fields can add sink, provenance, data class, argument hash,
and decision metadata.

## Validation in this repository

The trace schemas are compiled and applied to the real writer and renderer in
[`internal/trace/schema_test.go`](../internal/trace/schema_test.go):

```bash
go test ./internal/trace -run Published -v
```

The attack graph and import mapping schemas are validated against real Go
output in `internal/attackgraph` and `internal/logimport`.

Every published schema must also parse as strict JSON:

```bash
go test ./internal/lockfile -run PublishedSchemas -v
```

External consumers can validate with any draft 2020-12 implementation. A Python
`jsonschema` example, if that optional package is installed:

```python
import json
import jsonschema

with open("schemas/trace.schema.json", encoding="utf-8") as handle:
    schema = json.load(handle)

with open("caplock-trace.jsonl", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, 1):
        if line.strip():
            jsonschema.validate(json.loads(line), schema)
```

## Versioning

`trace.schema.json` and `replay.schema.json` both require `version: 1` today.
Breaking semantic changes require a new version with a documented migration.
Because the schemas reject unknown fields, adding a field is still a contract
change and must update the schema and its tests in the same pull request.

The `$id` values are canonical identifiers, not a promise that the repository is
already served from that domain. Distributed copies should retain the same
identifier and version metadata.
