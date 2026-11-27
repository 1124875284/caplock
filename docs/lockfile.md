# Lockfile format

`caplock.lock` records the MCP server surface that an agent was reviewed against.
It is designed to be committed, reviewed, and diffed in CI.

## Example

```json
{
  "version": 1,
  "servers": [
    {
      "name": "github",
      "source": ".mcp.json",
      "transport": "stdio",
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "url": null,
      "envKeys": ["GITHUB_TOKEN"],
      "headerKeys": [],
      "configHash": "sha256:..."
    }
  ]
}
```

## Guarantees

- Servers are sorted by `(name, source)`; env/header key names are sorted.
- No timestamp or machine-specific path is written.
- Env and header **values** are never written; only key names.
- `configHash` is the SHA-256 of the redacted server config serialized with
  sorted keys and compact separators. Rotating a secret does not create a diff;
  changing an env key, command, argument, URL, transport, or other field does.
- `source` is relative to the project root.
- Command arguments retain their original order because order can change runtime
  behavior.
- Empty required arrays are written as `[]`, never `null`.
- The same input produces byte-identical output across runs.

## Commands

```bash
caplock lock .                                  # write caplock.lock
caplock lock . --output path/to/caplock.lock    # choose output
caplock lock . --check                          # exit 1 if missing or stale
caplock lock . --connect                        # also capture tools/list
caplock diff old.lock new.lock --exit-code      # exit 1 on any change
```

`--check` compares the committed bytes with the canonical output, so whitespace
drift is caught. `diff` compares normalized permission semantics, so reordering
keys alone is not reported as a permission change.

When a server's tool manifest changes, `diff --json` includes `toolChanges` with
an `action` of `added`, `removed`, or `changed`, the tool name, and for changes
the affected fields: `description`, `inputSchema`, `annotations`, or
`capabilities`.

## Tool manifests

Lockfile v1 has an optional `tools` array populated by explicit connected mode:

```json
{
  "name": "read_file",
  "descriptionHash": "sha256:...",
  "inputSchemaHash": "sha256:...",
  "annotations": {"readOnlyHint": true},
  "capabilities": ["read"]
}
```

Static scans omit `tools` entirely. Its absence means the tool surface was not
collected, which is different from an explicitly empty tool list produced by a
connected server. Tool names, annotations, and capabilities are sorted and
deduplicated.

`descriptionHash` is the SHA-256 of the exact UTF-8 description, or of the empty
string when no description is supplied. `inputSchemaHash` is the SHA-256 of the
input schema after parsing and canonical JSON serialization: object keys are
sorted and the output is compact. Reordering schema keys therefore does not
create a diff, while changing a constraint, description, annotation, or derived
capability does.

Capabilities are a conservative keyword and annotation heuristic. They are a
review aid, not a trust boundary or proof of tool behavior. See
[connected mode](connect.md) for protocol and security details.

## Secrets

Put secrets in `env` or `headers`, not in `args` or URL query strings. Caplock
cannot reliably detect secrets embedded in command-line arguments or URLs, and
it writes those fields verbatim. Redaction is applied before hashing, so env and
header values do not affect `configHash`. Connected mode uses the values only to
start or authenticate the server; they are never serialized.

## Schema

The JSON Schema lives at [`schemas/caplock.lock.schema.json`](../schemas/caplock.lock.schema.json).
Breaking changes to this format bump `version`.
