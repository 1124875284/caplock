# Evidence and regression tests

Caplock turns a policy change into a replayable evidence run. A corpus declares
attack paths, the authorization request at each path, and the secure outcome.
The runner evaluates every request against the compiled Policy IR, checks
invariants, optionally compares a baseline policy, and renders a report.

This is deliberately deterministic: the corpus supplies request times and
provenance, and no LLM is present in the test path.

## Quickstart

```bash
# Embedded 50-case MCP baseline.
caplock test caplock.yaml

# Custom corpus plus a previous policy and lockfile coverage.
caplock test caplock.yaml \
  --corpus attacks.yaml \
  --baseline previous-policy.yaml \
  --lockfile caplock.lock \
  --subject finance-analyst

# Inspect and export evidence.
caplock report caplock.yaml --format text
caplock report caplock.yaml --format json -o report.json
caplock report caplock.yaml --format html -o report.html
caplock report caplock.yaml --format sarif -o caplock.sarif
```

`caplock test` exits `1` when a case fails or an invariant is violated. Use
`--allow-failures` for report-only runs and `--fail-on-baseline-change` when any
decision change should block CI.

## Corpus format

Corpora are strict YAML or JSON, capped at 4 MiB and 1,000 cases. Unknown fields
and multiple YAML documents are rejected.

```yaml
version: 1
name: finance-attacks
description: Prompt injection, exfiltration, and destructive actions
cases:
  - id: external-web-to-email
    description: External web content reaches an email sink
    severity: critical
    tags: [prompt-injection, exfiltration]
    path:
      - tool: web.fetch
        capabilities: [read, external, network]
        note: untrusted content enters the context
      - tool: email.send
        sink: email.send
        note: content leaves the agent
    request:
      subject: finance-analyst
      tool: email.send
      capabilities: [comms, external, network]
      sink: email.send
      provenance: [external_web]
      args:
        to: outside@example.com
        body: "<untrusted content>"
      context:
        time: "2026-11-26T10:00:00+08:00"
        environment: production
    expect:
      effect: require_approval
      rule: approve-external-provenance-egress
      obligations: [human_approval]
```

### Case fields

| Field | Meaning |
| --- | --- |
| `id` | Unique case ID |
| `description` | Human-readable summary |
| `severity` | `info`, `low`, `medium`, `high`, or `critical` |
| `tags` | Free-form grouping labels |
| `path` | Declared source/tool/sink steps for report context |
| `request` | The exact deterministic authorization input |
| `expect.effect` | `allow`, `deny`, or `require_approval` |
| `expect.rule` | Optional expected rule ID |
| `expect.default` | Optional expected default-decision flag |
| `expect.obligations` | Obligations that must be present |

The `path` is report metadata. The runner evaluates the single `request` at the
end of the path; it does not replay intermediate tool calls. Use
`caplock graph` to infer candidate source-to-sink paths from a captured tool
inventory and evaluate their sink requests.

If `request.context.time` is omitted, the runner uses the fixed instant
`2026-01-01T12:00:00Z`, not the wall clock. This keeps CI reproducible; set the
time explicitly when a case depends on a business-hours window.

## Invariants

### Delegation attenuation

For a subject with `parent` and `delegation: attenuate-only`, the runner
evaluates the same request as the parent and fails if the child decision is
weaker than the parent decision. The strength order is `deny` >
`require_approval` > `allow`.

### Tool coverage

When `--lockfile` is supplied, every locked tool must be selected by at least one
rule using `tool` or `capability`. A rule that relies only on time, provenance,
arguments, environment, data class, or sink is reported as `conditional` and
does not count as coverage. Use `caplock matrix POLICY --lockfile caplock.lock`
to review the baseline decision and candidate rules for each covered tool.

## Baseline differences

`--baseline previous-policy.yaml` evaluates the same corpus against the previous
policy and records changes in effect, matched rule, or default status. Baseline
changes are informational by default; use `--fail-on-baseline-change` to make
any change blocking.

## Reports

`report.Build` produces:

- summary counts: total, passed, failed, blocked, approval required, allowed,
  critical gaps, covered tools, uncovered tools
- a blast-radius summary for high/critical cases: allowed, approval required,
  blocked, exposed case IDs, tools, capabilities, and sinks
- attack paths ordered by severity
- policy gaps from failed cases, invariants, and coverage
- delegation violations
- baseline changes

Renderers:

- `text`: terminal review
- `json`: stable machine contract
- `html`: dependency-free local report; untrusted strings are escaped with
  `html/template`
- `sarif`: SARIF 2.1.0 results for code scanning

The blast radius is an evidence summary, not a risk score. It reports the
concrete high/critical paths that remain allowed, and the tools, capabilities,
and sinks declared on those paths. It does not invent a numeric severity or
claim to cover paths that are absent from the corpus.

## Trace replay

A corpus declares expected outcomes. A trace records what actually happened.
`caplock proxy --trace` captures replayable tool-call decisions, and
`caplock replay` compares them with a revised policy:

```bash
caplock replay caplock-trace.jsonl --policy caplock.yaml --fail-on-weakened
```

The replay reports changed, weakened, and strengthened decisions. Argument
hashes are captured by default; use `--trace-arguments full` only when the trace
file is approved to contain raw payloads. See [trace capture and
replay](trace.md).

## Generate corpus candidates from a trace

`caplock corpus` turns observed calls into a corpus whose expectations reflect
the current policy:

```bash
caplock corpus caplock-trace.jsonl --policy caplock.yaml -o candidates.yaml
caplock test caplock.yaml --corpus candidates.yaml
```

Every generated case is tagged `trace-generated, review-required`. The
expectation is a snapshot of current behavior, not proof of least privilege.
Redacted or missing arguments are recorded as partial candidates instead of
being guessed back into existence.

## Attack graph

`caplock graph` uses the captured lockfile to infer source, intermediate, and
sink roles from tool names and capability labels, then evaluates direct and
one-intermediate paths through the same policy engine:

```bash
caplock graph caplock.yaml \
  --lockfile caplock.lock \
  --subject finance-analyst \
  --max-paths 100 \
  --fail-on-exposed
```

Each path is marked `blocked`, `approval_required`, or `allowed`. The graph is
heuristic: it does not read tool responses, prove content flow, or model deeper
agent planning. Rules whose arguments are needed are marked
`argumentDependent` because the graph evaluates with empty arguments.

## Built-in corpus

The embedded baseline has 50 cases and is exercised against the bundled
`examples/policy` policy. It covers:

- prompt injection into email, Slack, and webhooks
- secret egress to email, HTTP, Slack, and upload sinks
- destructive database, key, repository, file, and log operations
- identity and finance privilege escalation
- after-hours finance writes and approvals
- shell execution and network-capable shell tools
- delegated child agents
- tool poisoning and newly introduced helper tools
- unknown-tool default deny

## Limitations

- Provenance and data classes are supplied by the caller. Caplock does not
  perform DLP, taint tracking, or content classification.
- Corpus paths are declared; attack-graph paths are inferred heuristically. The
  evaluator proves each concrete request, not every possible multi-step chain.
- The embedded corpus is a baseline, not a universal policy test. Projects
  should add corpus cases for their own tools, data, and approval process.
