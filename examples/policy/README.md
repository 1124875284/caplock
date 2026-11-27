# Policy example

```bash
caplock draft examples/policy/security-brief.txt --name finance-draft \
  --subject finance-analyst --parent orchestrator --output /tmp/caplock-draft.yaml
caplock lint /tmp/caplock-draft.yaml --strict
caplock lint examples/policy/caplock.yaml --strict
caplock compile examples/policy/caplock.yaml
caplock compile examples/policy/caplock.yaml --format json --output /tmp/policy.ir.json
caplock test examples/policy/caplock.yaml
caplock report examples/policy/caplock.yaml --format text
caplock export examples/policy/caplock.yaml --format rego --output /tmp/policy.rego
```

The compiler is deterministic and does not call an LLM. `draft` accepts only a
documented template grammar and reports unrecognized statements by line; use
`caplock draft --list-templates` to inspect it. `lint` reports semantic
review findings such as conflicting rules, unknown parent agents, delegation
cycles, and wildcard selectors. `policy.ir.json` is the committed golden output
for this source file; `internal/policy/policy_test.go` fails when the two drift.

The same policy source compiles, lints, evaluates the embedded 50-case attack
corpus, renders evidence, and exports to a runtime artifact. See [Policy
compilation](../../docs/policy.md), [Evidence](../../docs/evidence.md), and
[Export](../../docs/export.md) for the full contracts.
