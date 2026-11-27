# Connected mode

Caplock is static by default. `scan` and `lock` do not execute server commands
or open remote connections unless `--connect` is present.

```bash
caplock scan . --connect
caplock scan . --connect --json
caplock lock . --connect --output caplock.lock
caplock lock . --connect --check
```

`--timeout` sets a per-server deadline; the default is 20 seconds.

The repository includes a local fake server you can use without npm or network
access:

```bash
caplock scan examples/connected --connect
caplock lock examples/connected --connect --output /tmp/caplock-connected.lock
```

## What happens

For each discovered server, Caplock:

1. Sends an MCP `initialize` request and the `notifications/initialized`
   notification.
2. Calls `tools/list`, following `nextCursor` pagination.
3. Validates tool names and requires every tool to have an object input schema.
4. Hashes each description and canonicalized input schema with SHA-256.
5. Classifies the tool into `read`, `write`, `execute`, `network`, `identity`,
   `finance`, `comms`, `destructive`, `external`, or `unknown`.
6. Writes the normalized manifest to `caplock.lock`.

The negotiated protocol version is recorded only in memory and is sent on later
HTTP requests. Lockfile v1 currently stores normalized results, not the raw
protocol transcript.

## Transports

### stdio

The configured command is started in the project root with the current process
environment plus the server's configured `env` values. JSON-RPC messages use one
JSON object per line.

Caplock drains server stderr without printing it. This avoids leaking secrets
that an unreliable server might write to its logs.

### Streamable HTTP

The configured `url` must be an absolute `http` or `https` URL without embedded
user credentials or a fragment. Configured `headers`, such as `Authorization`,
are sent only in connected mode.

Caplock supports JSON and `text/event-stream` responses, captures
`Mcp-Session-Id`, and sends the negotiated `MCP-Protocol-Version` header on
subsequent requests. Redirects are disabled. HTTP response bodies are bounded
and are not echoed in errors.

Legacy SSE-only transport and custom transports are rejected rather than being
silently treated as Streamable HTTP.

## Safety properties

- The project config is untrusted input. `--connect` is authorization to run or
  contact the servers in that specific project.
- Commands in `args` and URLs are not secret-redacted. Keep credentials in
  `env` or `headers`.
- Env and header values are used only while building the connection. They are
  not written to stdout, errors, or the lockfile.
- Raw tool descriptions and schemas are not persisted. Only hashes, names,
  annotation hints, and derived capabilities are written.
- Malformed JSON-RPC, duplicate tool names, repeated pagination cursors, missing
  schemas, oversized messages, and exceeding page/tool limits abort the lock.
- Connected locks are still deterministic: tools and capabilities are sorted
  and no timestamps or absolute paths are written.

## Capability classification

Classification is a deterministic keyword and annotation heuristic. It is meant
to make review easier, not to prove what a tool does. A tool with no recognized
signal is labeled `unknown`, never assumed safe. MCP annotations are treated as
hints, not a trust boundary.

Expect false positives and false negatives. The next policy layer must express
explicit rules and regression cases rather than relying on labels alone.
