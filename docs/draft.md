# Constrained natural-language policy drafting

`caplock draft` turns a short security brief into `caplock/v1alpha1` YAML. It is
deliberately a **template compiler**, not a general-purpose natural-language
model or an LLM. A statement either maps to a documented template or fails with
a line-level diagnostic. Generated YAML is validated and must still pass
`caplock lint` and `caplock test`.

```console
$ caplock draft policy-brief.txt --name finance-draft \
    --subject finance-analyst --parent orchestrator -o caplock.yaml
wrote caplock.yaml (9 rules, 10 statements mapped)

$ caplock lint caplock.yaml
No policy lint findings.
```

## Why templates

Enterprise policy language is ambiguous. A compiler that silently guesses can
create a policy that looks secure but is not. Caplock therefore makes the
boundary explicit:

- Only listed templates are recognized.
- `@template <id>` forces a template when wording is ambiguous.
- Unrecognized statements fail closed and are never silently dropped.
- No statement, policy, tool description, or trace is sent to an LLM.
- The output is ordinary reviewable YAML with source rules and obligations.

## Supported statements

`caplock draft --list-templates` prints the current list. Examples include:

| Template | Example statement |
| --- | --- |
| `delegation-attenuate-only` | `Child agents must not exceed their parent permissions.` |
| `deny-privileged-path-write` | `Deny writes below /etc/.` |
| `deny-admin-role-assignment` | `Deny assignment of admin, owner, or superuser roles.` |
| `deny-secret-egress` | `Deny secret data from leaving through email or upload tools.` |
| `deny-external-provenance-egress` | `External web content must not flow to email tools.` |
| `require-approval-external-provenance` | `Require approval when external web content reaches Slack.` |
| `deny-finance-after-hours` | `Finance tools are forbidden outside Mon-Fri 09:00-18:00 Asia/Shanghai.` |
| `require-approval-pii-egress` | `Require approval when PII is sent externally.` |
| `require-approval-writes` | `Require approval for all write operations.` |
| `allow-read-only` | `Allow read-only operations.` |

Chinese statements are accepted for the same templates. For example:

```text
子 Agent 权限不得超过父 Agent。
财务类工具禁止在非工作时间调用。
外部网页内容不得流入发邮件工具。
```

Use `@template` when a brief contains words that could fit more than one rule:

```text
@template require-approval-pii-egress
Personal data must be reviewed before it leaves the agent.
```

## Generated output

The generated policy uses default deny, a subject named by `--subject`, and the
rule priorities/obligations defined by the template. A delegation statement
adds a parent subject and marks the child `attenuate-only`. The command refuses
to overwrite an existing output file unless `--force` is passed.

The intended workflow is:

```bash
caplock draft policy-brief.txt -o caplock.yaml
caplock lint caplock.yaml --strict
caplock test caplock.yaml
git add caplock.yaml
```

## Limits

- This is not arbitrary English/Chinese understanding.
- It does not discover tools, infer data flow, or choose a policy for you.
- It never executes an MCP server and never contacts an LLM.
- Generated rules are candidates; a human must review the diff and run the
  project's own regression corpus.
