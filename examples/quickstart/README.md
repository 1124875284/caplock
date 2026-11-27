# Quickstart

From the repository root:

```bash
caplock scan examples/quickstart
caplock lock examples/quickstart --output examples/quickstart/caplock.lock
caplock diff examples/quickstart/caplock.lock examples/quickstart/caplock.lock

# Optional: execute/contact these servers and lock their tool manifests.
caplock lock examples/quickstart --connect --output /tmp/connected.lock
```

The generated lockfile must not contain `example-token`. Caplock records env key
names and a redacted config hash, never env values. The checked-in example uses
static locks so the test suite does not download or execute `npx` packages.
