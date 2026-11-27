# Benchmark baseline

The benchmark is a deterministic behavior baseline, not a cross-platform speed
SLA. It answers a narrower question: did graph search, permission-matrix output,
or the 50-case regression corpus change without an intentional policy update?

Run it locally:

```bash
./bench/run.sh
```

The harness:

1. builds the CLI;
2. generates 20 synthetic MCP servers with `bench/gen`;
3. runs attack-graph search with a bounded path count;
4. renders the permission matrix; and
5. runs the embedded 50-case regression corpus.

It does not install packages, contact a remote MCP server, publish artifacts, or
deploy anything.

## Current baseline

The source of truth is [`bench/baseline.txt`](../bench/baseline.txt):

```text
graph_summary=servers=20 tools=20 sources=3 sinks=9 paths=189 blocked=147 approval_required=42 allowed=0 argument_dependent=0 truncated=false
corpus=PASS (50/50 cases)
```

`bench/run.sh` parses the graph summary and corpus result and fails on drift. The
expected success line is:

```text
benchmark: PASS (20 synthetic servers, 50 scenarios)
```

Update `bench/baseline.txt` only when policy, corpus, or graph semantics change
intentionally. A baseline update is a review event: explain why path counts,
blocked/approval counts, or corpus outcomes changed.

## Interpretation

- Counts describe the checked-in synthetic inventory and policy. They are not a
  claim about a customer's real tools.
- Path counts are bounded by the command's `--max-paths` value. The baseline uses
  the harness defaults.
- The graph is heuristic and argument-independent: it searches direct and
  single-intermediate source-to-sink paths, evaluates empty arguments, and does
  not inspect tool responses or prove content-level data flow.
- Wall-clock timing is intentionally not recorded because machine and CI runner
  differences make it noisy. If needed, time the command locally and report the
  environment with the result.
- A green benchmark is regression evidence, not proof that an agent is safe.

The CI `e2e and release contract` job runs this baseline alongside the demo and
security negative suite.
