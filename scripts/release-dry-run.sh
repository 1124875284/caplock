#!/usr/bin/env bash
# Validate the release contract and build local artifacts. This never publishes,
# pushes, uploads, or deploys anything.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

TMP=$(mktemp -d "${TMPDIR:-/tmp}/caplock-release-dry-run.XXXXXX")
cleanup() {
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "== release metadata =="
go test ./internal/releasechecks -v

echo "== module integrity =="
go mod verify

echo "== native build =="
mkdir -p "$TMP/bin" "$TMP/gobin"
go build -trimpath -ldflags '-s -w -X github.com/caplock/caplock/internal/version.Version=0.1.0-dry-run' -o "$TMP/bin/caplock" ./cmd/caplock

echo "== install path =="
GOBIN="$TMP/gobin" go install -trimpath ./cmd/caplock
"$TMP/gobin/caplock" version

echo "== cross-builds =="
mkdir -p "$TMP/cross"
for target in \
  linux/amd64 \
  linux/arm64 \
  darwin/amd64 \
  darwin/arm64 \
  windows/amd64; do
  os=${target%/*}
  arch=${target#*/}
  output="$TMP/cross/caplock-$os-$arch"
  if [ "$os" = "windows" ]; then output="$output.exe"; fi
  echo "  $target"
  GOOS="$os" GOARCH="$arch" CGO_ENABLED=0 go build -trimpath -o "$output" ./cmd/caplock
done

echo "== schemas and generated artifacts =="
go test ./internal/lockfile ./internal/trace ./internal/attackgraph ./internal/logimport -count=1
for schema in schemas/*.schema.json; do
  python3 -m json.tool "$schema" >/dev/null
done

echo "== optional packagers =="
if command -v goreleaser >/dev/null 2>&1; then
  goreleaser check
  mkdir -p "$TMP/goreleaser-src"
  rsync -a \
    --exclude '.git' \
    --exclude '.idea' \
    --exclude 'bin' \
    --exclude 'dist' \
    --exclude 'demo/output' \
    "$ROOT/" "$TMP/goreleaser-src/"
  (cd "$TMP/goreleaser-src" && goreleaser build --snapshot --clean)
else
  echo "goreleaser: skipped (not installed)"
fi

if command -v docker >/dev/null 2>&1; then
  docker build --tag caplock:release-dry-run .
else
  echo "docker: skipped (not installed)"
fi

echo
echo "release dry-run: PASS"
echo "nothing was published, uploaded, or deployed"
