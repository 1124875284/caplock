# Permission matrix

`caplock matrix` renders the baseline least-privilege decision for every tool
captured in a lockfile. It answers one review question:

> With the current policy, what happens when this subject calls each locked tool
> using only the capabilities recorded in the lockfile?

The result is a review artifact, not a second policy language. It is produced
from the same Policy IR and evaluator used by `caplock test` and
`caplock proxy`.

## Quickstart

Capture tools first. A static lockfile has no tool manifests, so the matrix
needs `lock --connect` or any lockfile that already contains a `tools` array.

```bash
caplock lock examples/connected --connect -o /tmp/caplock-connected.lock

caplock matrix examples/policy/caplock.yaml \
  --lockfile /tmp/caplock-connected.lock \
  --subject finance-analyst
```

Write a machine-readable artifact:

```bash
caplock matrix caplock.yaml \
  --lockfile caplock.lock \
  --subject finance-analyst \
  --format json \
  -o permission-matrix.json
```

## Output

The text format shows one row per locked server/tool:

```text
Caplock permission matrix
Policy: finance-agent
Subject: finance-analyst
Evaluation time: 2026-01-01T12:00:00Z
Default effect: deny
Summary: tools=3 allowed=1 approval_required=0 denied=2 defaulted=1 conditional=1

SERVER  TOOL               CAPABILITIES       BASE EFFECT  RULE                   CONDITIONAL
demo    delete_repository  destructive,write  deny         deny-destructive       false
demo    read_file          read               allow        allow-read-only-tools  false
demo    send_email         comms,external     deny         (default)              true
```

Each row reports:

| Field | Meaning |
| --- | --- |
| `server` / `tool` | Locked MCP identity |
| `capabilities` | Sorted capability labels from `caplock.lock` |
| `baseEffect` | Baseline decision: `allow`, `deny`, or `require_approval` |
| `ruleId` | Rule that produced the baseline decision; empty for a default decision |
| `default` | Whether no rule matched and `defaults.effect` was used |
| `conditional` | Whether any rule covering this tool also depends on request-time facts |
| `candidateRules` | JSON/YAML only: rules that cover the tool/capability pair and their conditional status |

Formats are deterministic:

- `text`: terminal review, with control characters escaped
- `json`: stable object with `entries`, `summary`, and `evaluationTime`
- `yaml`: the same document as JSON
- `csv`: one row per tool; arrays are joined with `|`

## Baseline semantics

Every row evaluates this request:

```json
{
  "subject": "<--subject>",
  "tool": "<locked tool>",
  "capabilities": ["<locked capabilities>"],
  "context": {"time": "<--time or 2026-01-01T12:00:00Z>"}
}
```

The baseline deliberately does **not** invent `dataClass`, `args`,
`provenance`, `sink`, `environment`, or attributes. Those facts belong to a
specific call, not to a tool manifest. Supplying fake values would make the
matrix look more complete than the evidence supports.

Consequences:

- A rule that matches on capability alone appears as the `baseEffect`.
- A rule that also needs scope, provenance, arguments, or a sink may not match
  the baseline. The tool can still be reported as `conditional: true`, with the
  rule listed in `candidateRules`.
- `conditional: true` means "this row is not the whole decision surface", not
  "the conditional rule fired".
- `default: true` means the capability-only portion of the policy produced no
  match. It does not mean the tool is ungoverned.

For example, a rule requiring approval only when provenance contains
`external_web` cannot be evaluated from a lockfile alone. The matrix shows the
baseline deny/default plus the candidate approval rule; the evidence corpus is
where the provenance fact is supplied and the approval path is proved.

## Review workflow

1. `caplock lock --connect` records the actual tool surface.
2. `caplock lint --strict` checks policy structure and delegation.
3. `caplock matrix` reviews the baseline allow/deny surface per tool.
4. `caplock test --lockfile` proves attack cases and reports uncovered tools.
5. `caplock report` renders blast radius, gaps, and attack paths for review.
6. `caplock proxy` enforces the same Policy IR at runtime.

The matrix is useful in pull requests because a tool or capability change
produces a visible row change. It is not a replacement for the corpus: a
green matrix does not prove that prompt injection, secret egress, or delegated
agents are contained.

## Flags

| Flag | Default | Meaning |
| --- | --- | --- |
| `--lockfile` | `caplock.lock` | Lockfile containing captured tools |
| `--subject` | `agent` | Subject evaluated for every row |
| `--format` | `text` | `text`, `json`, `yaml`, or `csv` |
| `--time` | `2026-01-01T12:00:00Z` | RFC3339 evaluation instant |
| `--output`, `-o` | stdout | Write the artifact to a file |

Exit codes:

- `0`: matrix rendered
- `1`: policy lint found blocking errors
- `2`: usage, lockfile, format, or missing-tool error
- `3`: internal or filesystem error

## Limitations

- The matrix is single-subject. Run it once per agent identity when multiple
  subjects share a lockfile.
- It does not expand every combination of arguments, provenance, data classes,
  and sinks. Those combinations belong in a corpus with explicit expectations.
- It does not discover tools that are absent from the lockfile.
- It reports policy decisions, not runtime observations. A tool that was never
  called still gets a baseline row.
- Time windows use the `--time` instant. The default is fixed for reproducibility,
  so after-hours rules may appear as baseline decisions depending on the chosen
  instant.
