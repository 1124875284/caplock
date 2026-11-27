# Release checklist

This is the local release contract for the capability-only Caplock release. It
does not authorize a publish, upload, deployment, or remote restart. Those
actions require explicit approval in the current conversation.

## Scope freeze

In scope for this release:

- facts: MCP discovery, connected `tools/list`, deterministic lockfile, diff;
- intent: constrained template drafting, Policy IR, compile, lint;
- evidence: 50-case corpus, permission matrix, heuristic attack graph, trace
  corpus candidates, JSONL/CSV import, text/JSON/HTML/SARIF reports;
- execution: Rego/Cedar/YAML/JSON/SDK export, stdio/Streamable HTTP proxy,
  audit/alert/redact/rate-limit obligations, replay; and
- release engineering: local metadata checks, clean-room reproduction, CI e2e,
  benchmark baseline, and security negative checks.

Explicitly out of scope:

- accounts, multi-tenancy, SSO, hosted policy storage, approval UI, distributed
  rate limiting, or a production HA gateway;
- Biscuit export, content-level DLP/taint/proof, tool-response inspection, or a
  full causal audit chain;
- automatic GitHub code-scanning upload; and
- any publish, package upload, container push, or deployment.

## Repository identity

The module and public references must stay coherent:

```text
module github.com/1124875284/caplock
install github.com/1124875284/caplock/cmd/caplock@latest
action 1124875284/caplock@v0
```

`go test ./internal/releasechecks -v` validates the module path, README install
and Action references, issue links, composite Action shell fields, GoReleaser
targets/archives/checksum/SBOM config, release-tag workflow, Dockerfile stages
and static build settings, and the required scripts and Makefile targets.

## Required local checks

Run from the repository root:

```bash
gofmt -l cmd internal packs demo examples
go vet ./...
go test -shuffle=on -race ./...
GOOS=windows GOARCH=amd64 go build ./...
GOOS=linux GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
make release-check
make security-negative
make bench
make demo
make demo-verify
```

Run OPA parity when an OPA binary is available; do not report it as passed when
it was skipped:

```bash
make verify-rego OPA_BIN=/path/to/opa
```

Run the release dry run:

```bash
make release-dry-run
```

It performs a native build, `go install` into a temporary `GOBIN`, cross-builds,
schema checks, and optional local `goreleaser`/Docker checks. If a tool is not
installed, the script prints `skipped`; that is not a pass for that tool.

The clean-room script requires `rsync`; screenshot rendering additionally
requires Node.js, the Playwright CLI, and Chrome. The Go toolchain and Python 3
are required for the demo and schema checks.

Reproduce from a copy without `.git`, build outputs, or demo output:

```bash
./scripts/clean-room.sh
# When Node, Playwright, and Chrome are available:
./scripts/clean-room.sh --with-screenshots
```

The release is capability-complete only when the required checks pass. Optional
tool gaps must remain visible in the final report.

## Artifact review

For an approved release later, inspect rather than assume:

- `checksums.txt` is present and every downloaded archive matches it;
- the SBOM is present and corresponds to the archive;
- archive contents include `LICENSE`, `NOTICE`, `README.md`, `CHANGELOG.md`,
  `SECURITY.md`, `schemas/*`, and `packs/*`;
- `caplock version` reports the intended version;
- the composite Action resolves `go.mod`, refreshes a lockfile, and produces the
  expected drift exit code;
- Docker runs as the distroless nonroot user and does not require CGO; and
- the release notes state the explicit limits from the README.

## Manual release gate

Before any tag, push, publish, or deployment, obtain explicit user approval in
the current conversation. Then:

1. freeze the version and update `CHANGELOG.md`;
2. re-run the required checks on the exact commit;
3. create the tag only after approval;
4. let the tag workflow build artifacts and SBOM/checksums;
5. verify downloaded artifacts and checksums after publication; and
6. record the result and any skipped optional checks.

Until that gate is crossed, the correct status is **configured but not
published**. Do not describe local dry-run output as a released artifact.
