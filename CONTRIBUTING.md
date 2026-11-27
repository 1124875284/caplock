# Contributing

Thanks for helping make agent permissions reviewable.

## Setup

Requirements: Go 1.24 or newer.

```bash
git clone https://github.com/1124875284/caplock.git
cd caplock
go mod download
make build
./bin/caplock version
```

## Checks

```bash
make fmt-check
make vet
make test
make release-check
make security-negative
make lint
```

`golangci-lint` v2 is required for `make lint`:

```bash
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0
```

For changes that affect parsing or lockfile validation, run the fuzz targets:

```bash
make fuzz
```

For user-visible or release-facing changes, also run:

```bash
make demo
make demo-verify
make bench
make release-dry-run
```

CI runs tests on Linux, macOS, and Windows, plus race tests, lint,
`govulncheck`, the release contract, security negative checks, and a Linux e2e
job that runs the demo and benchmark baseline.

## Pull requests

- Keep changes small and focused.
- Add or update tests for behavior changes.
- Update `README.md`, `docs/`, and `CHANGELOG.md` when needed.
- Do not include real tokens, customer configs, or production traces.
- Treat lockfile and schema changes as public API changes.
- Sign off commits with the Developer Certificate of Origin:

```bash
git commit -s
```

## Good first issues

- Add a parser for another MCP client config layout.
- Add a fixture for a tricky transport or JSONC edge case.
- Improve an error message without echoing configuration values.
- Add a lockfile schema example.
- Add a fake MCP server fixture for a transport or pagination edge case.

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).
