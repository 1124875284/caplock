# Caplock

**The capability lockfile for MCP agents.**

Caplock discovers the MCP servers an agent can use, optionally captures their
tool manifests, writes a deterministic `caplock.lock`, and makes permission
drift reviewable in every pull request. It also compiles human-authored
`caplock.yaml` policy into deterministic, lintable Policy IR.

```console
$ caplock scan examples/quickstart
SERVER      SOURCE     TRANSPORT  COMMAND / URL
filesystem  .mcp.json  stdio      npx -y @modelcontextprotocol/server-filesystem ./workspace
github      .mcp.json  stdio      npx -y @modelcontextprotocol/server-github

2 servers · 1 config file

$ caplock lock examples/quickstart -o examples/quickstart/caplock.lock
wrote examples/quickstart/caplock.lock (2 servers)

$ caplock lock . --connect -o caplock.lock
wrote caplock.lock (2 servers, 14 tools)

$ caplock diff old.lock new.lock --exit-code
+ filesystem (.mcp.json) added server
~ github (.mcp.json) config changed
  ~ tool create_issue (description, inputSchema, capabilities)
```

> **Status: v0.1.0-dev.** The fact, intent, evidence, and execution layers are
> implemented: static discovery, deterministic locking, `tools/list` capture,
> constrained natural-language drafting, Policy IR compilation/lint,
> deterministic evaluation, a 50-case regression corpus, heuristic attack-graph
> search, trace-generated corpus candidates, JSONL/CSV log import, JSON/HTML/
> SARIF reports, Rego/Cedar/YAML/JSON/SDK export, stdio/HTTP MCP proxies with
> runtime obligations, and replayable trace capture with published schemas.
> There is no hosted control plane, account system, multi-tenancy, SSO, or
> approval UI in this release.

## Why

MCP makes it easy to give an agent new capabilities: read code, query a
production database, send email. But the permission surface is scattered across
config files, tool descriptions, and policy documents. Reviewers cannot answer a
simple question:

> What changed in this PR, and what can the agent do now that it could not do before?

**Caplock turns scattered MCP tool permissions into permission artifacts that
can be committed, diffed, tested, and enforced.** Its wedge is **policy
compilation + deterministic regression + permission diff**. It closes the loop
from the permission surface an agent actually exposes to the policy a runtime
actually executes:

```text
discover surface → lock baseline → review change → compile policy
                 → regression-test → report evidence → enforce at runtime
```

## Four layers, four reviewable answers

- **Facts — `scan`, `lock`, `matrix`.** Finds the MCP servers and tools an agent
  can use, captures descriptions and schemas as hashes, classifies capabilities,
  and writes a deterministic `caplock.lock` plus a subject-by-tool permission
  matrix. Secrets are represented by key names, never values.
- **Intent — `draft`, `compile`, `lint`.** Turns a constrained set of English or
  Chinese security statements into `caplock.yaml`, then compiles it into Policy
  IR with source locations. Lint catches default-allow, broad wildcards,
  delegation escalation, conflicting rules, and similar review failures.
- **Evidence — `graph`, `test`, `report`, `corpus`, `import`.** Runs a 50-case
  corpus, infers bounded source-to-sink paths from the lockfile, turns captured
  traces into review-required regression candidates, and imports historical
  JSONL/CSV logs through an explicit mapping. It checks invariants and baseline
  decisions, then emits text, JSON, HTML, or SARIF with attack paths, policy
  gaps, blast radius, and tool coverage.
- **Execution — `export`, `proxy`, `replay`.** Exports Rego, Cedar, YAML, JSON,
  or SDK-neutral config, and enforces the same IR at a stdio or Streamable HTTP
  MCP proxy. The proxy is fail-closed, supports `allow`, `deny`, and
  `require_approval`, enforces audit/alert/redact/rate-limit obligations, and
  records hash-only audit plus replayable trace data.

The intent layer is deliberately bounded: `draft` is a deterministic template
compiler, not an LLM guessing at arbitrary prose. Compilation, lint, evaluation,
and the CI path do not depend on a model.

## What it fixes

| Problem | What Caplock makes visible |
| --- | --- |
| **Agent permissions are invisible** | A PR that adds an MCP server or tool is reduced to concrete tools, schema hashes, and capabilities in a committed lockfile. |
| **Permission changes are hard to review** | `diff` reports added, removed, and changed servers, tools, and capabilities instead of leaving reviewers to infer risk from code. |
| **Tool descriptions change silently** | Description and input-schema hashes expose supply-chain or server-side manifest drift. |
| **Security policy cannot reach code** | A bounded drafting grammar produces reviewable `caplock.yaml`; compilation and lint turn it into typed Policy IR before enforcement. |
| **A policy fix creates another gap** | Fixed attack cases, invariants, baseline diffs, and trace replay make regressions repeatable. |
| **Reports do not enter engineering workflows** | Stable exit codes, structured output, and SARIF connect findings to CI and code scanning. |
| **There is no runtime execution point** | The reference proxy evaluates real `tools/call` requests and fails closed; exported rules can feed an existing gateway. |
| **Audit captures too much sensitive data** | Audit records contain decisions, rule IDs, capability labels, and argument hashes, not raw arguments or tool results. |

## Architecture

```mermaid
flowchart TB
    subgraph INPUTS["Inputs"]
        direction LR
        CFG["MCP configs"]
        TOOLS["tools/list manifests"]
        BRIEF["Security briefs"]
        LOGS["Historical logs"]
        CALL["Runtime tools/call"]
    end

    subgraph FACTS["1. Facts layer: make the tool surface visible"]
        direction LR
        SCAN["scan"] --> LOCK["lock"]
        LOCK --> LOCKFILE["caplock.lock"]
        LOCK --> DIFF["diff"]
        LOCK --> MATRIX["matrix"]
    end

    subgraph INTENT["2. Intent layer: compile reviewable policy"]
        direction LR
        DRAFT["draft"] --> POLICY["caplock.yaml"]
        POLICY --> LINT["lint"]
        POLICY --> COMPILE["compile"]
        COMPILE --> IR["Policy IR"]
    end

    subgraph EVIDENCE["3. Evidence layer: test what is allowed"]
        direction LR
        GRAPH["graph"] --> REPORT["report"]
        TEST["test"] --> REPORT
        REPORT --> REPORT_OUT["text / JSON / HTML<br/>SARIF"]
        IMPORT["import"] --> REPLAY["replay"]
        CORPUS["corpus<br/>review-required candidates"] --> TEST
        TRACE["trace<br/>hash-only JSONL"] --> CORPUS
        TRACE --> REPLAY
    end

    subgraph EXECUTION["4. Execution layer: emit or enforce the same decision"]
        direction LR
        EXPORT["export"] --> EXPORTS["Rego / Cedar / YAML<br/>JSON / SDK"]
        PROXY["proxy"] --> DECISION["allow / deny /<br/>require_approval"]
        PROXY --> TRACE
    end

    CFG --> SCAN
    CFG --> LOCK
    TOOLS --> LOCK
    BRIEF --> DRAFT
    LOGS --> IMPORT
    CALL --> PROXY

    LOCKFILE --> GRAPH
    LOCKFILE --> TEST
    LOCKFILE --> MATRIX
    IR --> GRAPH
    IR --> TEST
    IR --> REPORT
    IR --> MATRIX
    IR --> EXPORT
    IR --> PROXY
    IR --> REPLAY

    DECISION --> RESULT["runtime decision<br/>with named rule"]
    REPORT_OUT --> ARTIFACT["review / CI evidence"]
    EXPORTS --> ARTIFACT
    RESULT --> ARTIFACT
    TRACE --> ARTIFACT

    classDef inputStyle fill:#f6f8fa,stroke:#6e7781,color:#24292f
    classDef factsStyle fill:#ddf4ff,stroke:#0969da,color:#0a3069
    classDef intentStyle fill:#fff4d6,stroke:#b7791f,color:#4a2b00
    classDef evidenceStyle fill:#e8f7ee,stroke:#238636,color:#0b3d1e
    classDef executionStyle fill:#f3e8ff,stroke:#8250df,color:#35125f
    classDef artifactStyle fill:#ffffff,stroke:#57606a,color:#24292f

    class CFG,TOOLS,BRIEF,LOGS,CALL inputStyle
    class SCAN,LOCK,LOCKFILE,DIFF,MATRIX factsStyle
    class DRAFT,POLICY,LINT,COMPILE,IR intentStyle
    class GRAPH,TEST,REPORT,REPORT_OUT,IMPORT,REPLAY,CORPUS,TRACE evidenceStyle
    class EXPORT,EXPORTS,PROXY,DECISION,RESULT executionStyle
    class ARTIFACT artifactStyle
```

The core rule is simple: the same Policy IR drives the matrix, regression tests,
reports, exports, proxy decisions, and replay. There is no second policy
implementation hiding in a report or a runtime adapter.

<details>
<summary>Text fallback for renderers without Mermaid support</summary>

```text
INPUTS                              PIPELINE                            ARTIFACTS / ACTIONS
──────────────────────────────────  ───────────────────────────────────  ─────────────────────────────
MCP configs + tools/list          →  scan → lock → diff                 →  caplock.lock, matrix
Security briefs + caplock.yaml    →  draft → compile → lint            →  caplock.yaml, Policy IR
Captured lockfile                 →  graph → evaluate paths            →  source-to-sink report
Attack corpus + baseline policy   →  test → invariants → baseline diff  →  text / JSON / HTML / SARIF
Historical JSONL / CSV            →  import → replay                   →  normalized trace
Runtime tools/call                →  proxy → obligations → decide       →  allow / deny / approval
Captured trace                    →  corpus → review candidates        →  regression corpus
Policy IR                         →  export                            →  Rego / Cedar / YAML / JSON / SDK
```

</details>

## How it differs

| Existing category | What it answers | Where Caplock fits |
| --- | --- | --- |
| **Scanner** | “What risk exists now?” | Caplock also answers “what changed in this PR, and will the change regress a policy?” |
| **Gateway** | “How do I enforce calls?” | Caplock supplies the upstream policy source, regression evidence, and reviewable artifacts, then exports to an existing gateway or its reference proxy. |
| **Policy engine** (for example OPA) | “How do I evaluate a decision?” | Caplock is the authoring, compilation, testing, and change-review layer around a decision engine, not a replacement for one. |
| **Sandbox / DLP / proof system** | “Can I contain or prove the data flow?” | Caplock is a permission-artifact and reference-enforcement layer; it does not claim complete data-flow proof. |

It is deliberately not another opaque “AI security score.” The output is a
reviewable artifact, a reproducible test result, or a runtime decision with a
named rule.

## Who it is for

| Role | What changes |
| --- | --- |
| **Developer** | Adding an MCP tool becomes reviewable like changing a dependency: the PR shows the new capability and its policy impact. |
| **Security engineer** | Natural-language guardrails become testable, regressible, auditable policy artifacts instead of one-off review comments. |
| **Platform owner** | MCP tool permissions gain a baseline, CI gates, and a concrete runtime enforcement point. |
| **Engineering leader** | Agent permissions move from invisible configuration risk to a managed engineering asset. |

Caplock is not a sandbox, general-purpose gateway, or proof system. It is the
artifact and policy layer those systems need upstream: a permission inventory, a
testable policy, and a reference enforcement point.

## Install

Requirements: Go 1.24 or newer.

From source:

```bash
git clone https://github.com/caplock/caplock.git
cd caplock
make build
./bin/caplock version
```

Or install directly:

```bash
go install github.com/caplock/caplock/cmd/caplock@latest
```

## 10-minute local path

This path uses the bundled fake MCP server and generated fixtures. It does not
contact a remote MCP server or require npm. The first run may download Go module
dependencies.

```bash
make build

# 1. Capture a real MCP handshake from the bundled dependency-free server.
./bin/caplock lock examples/connected --connect -o /tmp/caplock-connected.lock

# 2. Run the deterministic 50-case regression corpus.
./bin/caplock test examples/policy/caplock.yaml

# 3. Generate a 20-server inventory and search bounded attack paths.
go run ./bench/gen -output /tmp/caplock-bench.lock
./bin/caplock graph examples/policy/caplock.yaml \
  --lockfile /tmp/caplock-bench.lock \
  --subject finance-analyst \
  --max-paths 10

# 4. Render a self-contained report for human review.
./bin/caplock report examples/policy/caplock.yaml \
  --lockfile /tmp/caplock-bench.lock \
  --subject finance-analyst \
  --format html -o /tmp/caplock-report.html
```

Expected signals: `PASS (50/50 cases)`, a graph summary with 20 tools, and an
HTML report at `/tmp/caplock-report.html`. The graph is a heuristic review aid:
it searches direct and one-intermediate-node source-to-sink paths and evaluates
them with empty arguments; it is not content-level data-flow proof.

## Quickstart

```bash
caplock scan examples/quickstart
caplock lock examples/quickstart -o examples/quickstart/caplock.lock
caplock lock examples/quickstart -o examples/quickstart/caplock.lock --check
caplock diff examples/quickstart/caplock.lock examples/quickstart/caplock.lock

# Explicitly contact each server and capture its tool manifest:
caplock scan . --connect --json
caplock lock . --connect -o caplock.lock

# Or try the bundled fake MCP server (no network or npm required):
caplock scan examples/connected --connect
caplock lock examples/connected --connect -o /tmp/caplock-connected.lock

# Review the baseline allow/deny surface for each captured tool:
caplock matrix examples/policy/caplock.yaml \
  --lockfile /tmp/caplock-connected.lock \
  --subject finance-analyst

# Draft from a constrained natural-language brief, then review and test it:
caplock draft examples/policy/security-brief.txt \
  --name finance-draft --subject finance-analyst --parent orchestrator \
  -o caplock.yaml
caplock lint caplock.yaml --strict
caplock test caplock.yaml

# Or create, lint, and compile a deterministic policy artifact:
caplock init
caplock lint caplock.yaml
caplock compile caplock.yaml -o policy.ir.json

# Or validate the bundled policy example:
caplock lint examples/policy/caplock.yaml --strict
caplock compile examples/policy/caplock.yaml

# Run the deterministic 50-case attack regression and render evidence:
caplock test examples/policy/caplock.yaml
caplock report examples/policy/caplock.yaml --format text
caplock report examples/policy/caplock.yaml --format sarif -o caplock.sarif

# Infer bounded source-to-sink paths from a captured tool inventory:
caplock graph examples/policy/caplock.yaml \
  --lockfile /tmp/caplock-connected.lock \
  --subject finance-analyst

# Export the same policy for a runtime:
caplock export examples/policy/caplock.yaml --format rego -o policy.rego
caplock export demo/fixtures/runtime-policy.yaml --format cedar -o policy.cedar
caplock export examples/policy/caplock.yaml --format sdk -o policy.sdk.json

# Enforce it in front of a stdio MCP server. The child starts only here.
caplock proxy \
  --policy examples/policy/caplock.yaml \
  --subject finance-analyst \
  --audit caplock-audit.jsonl \
  --alert caplock-alerts.jsonl \
  --trace /tmp/caplock-trace.jsonl \
  -- go run ./examples/fake-mcp

# Replay captured decisions, or turn them into review-required regression cases:
caplock replay /tmp/caplock-trace.jsonl --policy examples/policy/caplock.yaml
caplock corpus /tmp/caplock-trace.jsonl \
  --policy examples/policy/caplock.yaml \
  -o candidates.yaml

# Map a historical CSV or JSONL log through an explicit field mapping:
caplock import history.csv --mapping history-mapping.yaml -o imported.trace.jsonl
caplock replay imported.trace.jsonl --policy examples/policy/caplock.yaml
```

`scan` and `lock` parse configuration only by default. They never start or
contact an MCP server unless `--connect` is present.

## End-to-end demo

The repository includes a reproducible, local-only demo with 33 captured
scenarios. It exercises every CLI layer, a real stdio MCP handshake, policy
drafting/linting, the 50-case regression corpus, attack-graph search,
trace-generated corpus candidates, historical-log import, text/HTML/SARIF
reports, Rego/Cedar/YAML/JSON/SDK export, proxy allow/deny/approval, runtime
redaction/alert/rate-limit enforcement, trace privacy, replay weakening/
strengthening, JSON Schema tests, the benchmark, and the full verification
suite.

```bash
./demo/run.sh
./demo/screenshots.sh
./demo/verify.sh
```

No deployment, remote MCP server, npm package, or network call is involved. Set
`OPA_BIN=/path/to/opa` before `run.sh` to include real-OPA parity. See the
[demo guide](demo/README.md) for the scenario matrix and artifact layout.

![Permission matrix](demo/screenshots/13-matrix.png)

## Commands

| Command | What it does |
| --- | --- |
| `caplock scan [PATH]` | Discover MCP configs and print the server inventory. `--connect` also fetches tools; `--json` is machine-readable. |
| `caplock lock [PATH]` | Write a deterministic lockfile. `--connect` captures tools; `--check` fails with exit code 1 on drift. |
| `caplock diff OLD NEW` | Show added, removed, and changed servers and tools. Use `--exit-code` in CI and `--json` for tooling. |
| `caplock init [DIR]` | Create a starter `caplock.yaml`. Use `--force` to replace an existing file. |
| `caplock draft BRIEF` | Draft YAML from supported English/Chinese security statements. `--list-templates` shows the exact grammar; unknown statements fail closed. |
| `caplock compile [POLICY]` | Compile policy source into Policy IR. Supports `--format ir\|json` and `--output`. |
| `caplock lint [POLICY]` | Report policy review findings. `--strict` fails on warnings; `--json` is machine-readable. |
| `caplock matrix [POLICY]` | Render the baseline permission matrix for every tool captured in a lockfile. Supports `text`, `json`, `yaml`, and `csv`. |
| `caplock graph [POLICY]` | Infer bounded source-to-sink paths from a captured lockfile and evaluate each sink request. `--fail-on-exposed` gates allowed high/critical paths. |
| `caplock test [POLICY]` | Run the embedded 50-case corpus, invariants, coverage, and optional baseline diff. Exits 1 on failure. |
| `caplock report [POLICY]` | Render attack paths, gaps, and coverage as `text`, `json`, `html`, or `sarif`. |
| `caplock corpus TRACE` | Generate review-required corpus candidates from observed calls and the current policy. |
| `caplock import LOG` | Map generic JSONL or CSV tool-call logs into trace JSONL with an explicit `--mapping`. |
| `caplock export [POLICY]` | Export Policy IR as `rego`, `cedar`, `yaml`, `json`, or `sdk`. Cedar rejects unsupported selectors instead of approximating them. |
| `caplock proxy -- COMMAND` | Enforce policy on MCP `tools/call` over stdio; `caplock proxy http` handles Streamable HTTP. Supports audit, alert, redact, rate-limit, approval mode, and replayable traces. |
| `caplock replay TRACE` | Replay a captured trace against the current policy and report changed or weakened decisions. |
| `caplock version` | Print the version. |

`PATH` can be a project directory or a single MCP config file. Caplock discovers
`.mcp.json`, `mcp.json`, `mcp_config.json`, `.cursor/mcp.json`, `.vscode/mcp.json`,
and Claude Desktop config files while skipping dependency and build directories.
JSONC comments and trailing commas are accepted.

`--connect` is deliberately explicit because it changes Caplock from a parser
into a client: stdio servers are executed and HTTP servers receive the headers
configured in the project. Only connect to projects and endpoints you trust. A
per-server timeout defaults to 20 seconds and can be changed with `--timeout`.

Exit codes:

- `0`: success or no permission changes
- `1`: policy lint error, policy violation, or lockfile drift
- `2`: usage, configuration, or MCP connection error
- `3`: internal or filesystem error

## Lockfile

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
      "configHash": "sha256:...",
      "tools": [
        {
          "name": "create_issue",
          "descriptionHash": "sha256:...",
          "inputSchemaHash": "sha256:...",
          "annotations": {"readOnlyHint": false, "destructiveHint": false},
          "capabilities": ["network", "write"]
        }
      ]
    }
  ]
}
```

The lockfile is deterministic: servers and key names are sorted, no timestamp or
machine-specific path is written, and rotating a secret does not create a diff.

**Secrets:** env and header values are redacted before hashing. Values embedded
in command-line arguments or URL query strings cannot be detected reliably, so
do not put secrets in `args` or `url`.

The JSON Schema lives at
[`schemas/caplock.lock.schema.json`](schemas/caplock.lock.schema.json). Lockfile
v1 includes an optional `tools` array. It is omitted for static scans and is an
explicit empty array when a connected server exposes no tools.

Tool descriptions and input schemas are hashed, not stored. Capabilities are a
deterministic, conservative heuristic based on tool name, description, and MCP
annotations; they are review aids, not an authorization decision.

## Policy

`caplock.yaml` is compiled locally into Policy IR. The compiler rejects unknown
fields, duplicate IDs, empty selectors, invalid effects, and multiple YAML
documents. It never calls an LLM.

```yaml
apiVersion: caplock/v1alpha1
kind: PolicySet
metadata:
  name: finance-agent
spec:
  defaults:
    effect: deny
  rules:
    - id: external-to-email
      effect: require_approval
      match:
        sink: email.send
        provenance:
          contains: external_web
      obligations: [human_approval, redact]
```

`caplock lint` checks unknown parents, delegation cycles, undeclared subjects,
broad allows, wildcards, duplicate rules, and conflicting effects. `caplock
compile` emits normalized IR with source locations; errors block compilation,
while warnings remain reviewable and fail only with `lint --strict`.

The evaluator applies `deny` over `require_approval` over `allow`, then explicit
priority, then source order. It supports tool, capability, data class, sink,
argument, provenance, environment, time-window, and delegation checks. The
embedded corpus exercises prompt injection, secret egress, destructive actions,
privilege escalation, after-hours finance operations, shell execution, tool
poisoning, and unknown tools. Corpus requests carry explicit times so results
are reproducible.

See [Policy compilation and evaluation](docs/policy.md), [Evidence and
regression tests](docs/evidence.md), [Runtime proxy](docs/proxy.md), [Export
backends](docs/export.md), the [policy source schema](schemas/policy.schema.json),
and the [runnable example](examples/policy).

## GitHub Action

```yaml
- uses: caplock/caplock@v0
  with:
    path: .
    lockfile: caplock.lock
    fail-on-change: "true"
    policy: caplock.yaml
    fail-on-policy: "true"
```

The action builds Caplock from the action source, refreshes the lockfile, and
fails when the committed lockfile is out of date. When `policy` is set it also
lints, runs the regression corpus, and writes a SARIF report. It does not upload
configs or secrets.

## Design principles

- **Local-first.** No config, trace, or secret leaves the machine.
- **Deterministic.** The same input produces the same lockfile or Policy IR byte
  for byte.
- **Reviewable.** A human can read the lockfile and the PR diff.
- **Static by default.** Only explicit `--connect` executes a command or opens a
  remote connection.
- **Bounded input.** Configs, lockfiles, policy files, protocol messages, pages,
  and tool counts all have hard limits.
- **Small dependency surface.** Cobra and `yaml.v3` are the only direct runtime
  dependencies.
- **LLM optional.** Policy compilation, lint, and the CI path never depend on an
  LLM.
- **Constrained drafting.** `caplock draft` maps only documented templates and
  rejects ambiguous statements; it never silently guesses policy.
- **Private traces.** `proxy --trace` records argument hashes by default; raw
  arguments require explicit `--trace-arguments full`.
- **No control plane required.** The release is a local binary and library
  surface; accounts, multi-tenancy, SSO, hosted policy storage, and an approval
  UI are deliberately out of scope.

## Explicit limits

- The attack graph is heuristic. It uses lockfile capabilities, searches direct
  and single-intermediate paths, and does not inspect tool responses or prove
  content-level data flow. Argument-dependent rules are evaluated with empty
  arguments and marked `argumentDependent` in graph output.
- `draft` is a bounded template compiler, not an arbitrary natural-language
  policy generator. Unsupported or ambiguous statements fail closed.
- The proxy records requests and decisions, not model reasoning, tool responses,
  or a full causal audit chain. It does not perform DLP or taint tracking.
- Hash-only traces cannot prove argument-dependent decisions. Full traces are
  an explicit, sensitive opt-in and still do not make redacted fields
  recoverable.
- Biscuit export is not implemented. GitHub code-scanning auto-upload is not
  implemented; Caplock writes SARIF for an existing upload step.
- Accounts, multi-tenancy, SSO, hosted policy storage, an approval UI,
  distributed rate limiting, and a production HA gateway are not part of this
  release.
- GoReleaser, Dockerfile, and GitHub Action contracts are checked locally, but
  no binary, container, package, or release artifact is published by this
  development session.

## Roadmap

- **Milestone 1 (complete):** static MCP config discovery, server lockfile, redaction, diff, CI.
- **Milestone 2 (complete):** explicit MCP connection, `tools/list` manifests, capability inventory, tool-level diffs.
- **Milestone 3 (complete):** `caplock.yaml`, Policy IR, compile, lint, init, deterministic evaluation, argument/time selectors, and golden/fuzz coverage.
- **Milestone 4 (complete):** constrained natural-language drafting, 50-case evidence corpus, invariants, coverage, baseline diffs, per-tool permission matrices, blast-radius summaries, text/JSON/HTML/SARIF reports, and Rego export with optional OPA parity checks.
- **Milestone 5 (complete for the capability release):** trace capture and replay, trace-generated corpus candidates, explicit JSONL/CSV import, heuristic source-to-sink attack graph, Cedar/SDK export, runtime audit/alert/redact/rate-limit obligations, benchmark packs, and published trace/replay/attack-graph/import-mapping schemas.
- **Not planned for this release:** accounts, multi-tenancy, SSO, hosted policy storage, approval UI, distributed rate limiting, or a production HA gateway. Biscuit export and content-level DLP/proof remain explicit non-goals rather than hidden claims.

See [ADR 0001](docs/adr/0001-go-core-spec-first.md) for the architecture
rationale and the technical documentation below for layer and format details.

## Docs

- [Architecture](docs/architecture.md)
- [Benchmark baseline](docs/benchmark.md)
- [Connected mode](docs/connect.md)
- [Constrained policy drafting](docs/draft.md)
- [Demo guide](demo/README.md)
- [Evidence and regression tests](docs/evidence.md)
- [Export backends](docs/export.md)
- [Connected-mode example](examples/connected/README.md)
- [JSON Schemas](docs/schemas.md)
- [Lockfile format](docs/lockfile.md)
- [Permission matrix](docs/matrix.md)
- [Policy compilation](docs/policy.md)
- [Policy example](examples/policy/README.md)
- [Trace capture and replay](docs/trace.md)
- [Release checklist](docs/release-checklist.md)
- [Runtime proxy](docs/proxy.md)

## Visual verification gallery

Every image below is captured from real command output or a generated artifact.
The scenario ID matches `demo/output/<id>/` after running the demo.

### Overview and facts layer

![CLI overview](demo/screenshots/01-overview.png)

![Static MCP discovery](demo/screenshots/02-scan-static.png)

![Connected tool discovery](demo/screenshots/03-scan-connected.png)

![Deterministic lockfile](demo/screenshots/04-lock.png)

![Tool manifest diff gate](demo/screenshots/05-diff.png)

![Stale lockfile CI gate](demo/screenshots/06-lock-check.png)

### Intent layer

![Starter policy](demo/screenshots/07-init.png)

![English and Chinese policy drafting](demo/screenshots/08-draft.png)

![Constrained drafting templates](demo/screenshots/09-templates.png)

![Strict policy lint](demo/screenshots/10-lint.png)

![Default-allow lint gate](demo/screenshots/11-lint-gate.png)

![Deterministic Policy IR](demo/screenshots/12-compile.png)

### Evidence layer

![Permission matrix](demo/screenshots/13-matrix.png)

![50-case attack regression](demo/screenshots/14-test.png)

![Default-allow blast radius](demo/screenshots/15-test-fail.png)

![Text attack-path report](demo/screenshots/16-report-text.png)

![Generated HTML attack-path report](demo/screenshots/17-report-html.png)

![SARIF policy gaps](demo/screenshots/18-report-sarif.png)

![Source-to-sink attack graph](demo/screenshots/29-attack-graph.png)

![Trace-generated regression candidates](demo/screenshots/30-trace-corpus.png)

![Historical log import and replay](demo/screenshots/31-log-import.png)

### Execution layer

![Rego Cedar YAML JSON SDK exports](demo/screenshots/19-exports.png)

![Allowed proxy call](demo/screenshots/20-proxy-allow.png)

![Denied destructive proxy call](demo/screenshots/21-proxy-deny.png)

![Approval block and forward modes](demo/screenshots/22-proxy-approval.png)

![Hash-only trace capture](demo/screenshots/23-trace-capture.png)

![Unchanged replay](demo/screenshots/24-replay-unchanged.png)

![Weakened replay and CI gates](demo/screenshots/25-replay-weakened.png)

![Strengthened replay](demo/screenshots/26-replay-strengthened.png)

![Runtime redaction alert and rate limit obligations](demo/screenshots/32-proxy-obligations.png)

### Verification

![Published JSON Schema tests](demo/screenshots/27-schema-validation.png)

![Full local verification suite](demo/screenshots/28-verification.png)

![20-server 50-case benchmark](demo/screenshots/33-benchmark.png)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md)
or email [qq1124875284@163.com](mailto:qq1124875284@163.com).

## License

Apache-2.0. See [LICENSE](LICENSE).
