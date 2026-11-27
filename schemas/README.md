# Caplock JSON Schemas

The files in this directory are the published, versioned contracts for Caplock
artifacts. They use JSON Schema draft 2020-12 and are tested against real writer,
renderer, and report output.

| Contract | File |
| --- | --- |
| MCP capability lockfile | [`caplock.lock.schema.json`](caplock.lock.schema.json) |
| Policy source | [`policy.schema.json`](policy.schema.json) |
| Compiled Policy IR | [`ir.schema.json`](ir.schema.json) |
| Evidence corpus | [`evidence.schema.json`](evidence.schema.json) |
| Evidence report | [`report.schema.json`](report.schema.json) |
| Trace JSONL record | [`trace.schema.json`](trace.schema.json) |
| Trace replay JSON report | [`replay.schema.json`](replay.schema.json) |

`trace.schema.json` applies to one line of a JSONL trace, not the whole file.
`replay.schema.json` applies to `caplock replay --format json`.

See [`docs/schemas.md`](../docs/schemas.md) for validation examples, file limits,
privacy behavior, and versioning rules.
