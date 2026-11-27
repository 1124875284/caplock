# Connected-mode example

This example runs a local, dependency-free fake MCP server. No package download
or network connection is required.

From the repository root:

```bash
caplock scan examples/connected --connect
caplock lock examples/connected --connect --output /tmp/caplock-connected.lock
caplock diff /tmp/caplock-connected.lock /tmp/caplock-connected.lock
```

The server exposes three tools across two `tools/list` pages. The generated
lockfile contains tool hashes and capability labels, not raw descriptions.

You can also put the policy proxy in front of the fake server:

```bash
printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"/workspace/readme.md"}}}' | \
  caplock proxy \
    --policy examples/policy/caplock.yaml \
    --subject finance-analyst \
    --lockfile /tmp/caplock-connected.lock \
    --audit /tmp/caplock-audit.jsonl \
    -- go run ./examples/fake-mcp
```

The tool is allowed by the example policy and forwarded. A `delete_repository`
or `send_email` call is blocked locally. The audit file contains the decision
and an argument hash, not the raw arguments.
