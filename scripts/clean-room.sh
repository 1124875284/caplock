#!/usr/bin/env bash
# Reproduce Caplock from a clean copy of the working tree.
# This script is local-only: it never deploys, publishes, or contacts a remote
# MCP server. It may use the local Go module cache while building.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WITH_SCREENSHOTS=0
KEEP=0

usage() {
  cat <<'EOF'
Usage: scripts/clean-room.sh [--with-screenshots] [--keep]

  --with-screenshots  Also render the committed demo screenshots (requires npx,
                      Playwright, and Chrome).
  --keep              Keep the temporary clean-room directory for inspection.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --with-screenshots) WITH_SCREENSHOTS=1 ;;
    --keep) KEEP=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "clean-room: unknown argument $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

TMP=$(mktemp -d "${TMPDIR:-/tmp}/caplock-clean-room.XXXXXX")
cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    printf 'clean-room: kept %s\n' "$TMP"
  else
    rm -rf "$TMP"
  fi
}
trap cleanup EXIT

mkdir -p "$TMP/src"
echo "== copy working tree =="
rsync -a \
  --exclude '.git' \
  --exclude '.idea' \
  --exclude '.DS_Store' \
  --exclude 'bin' \
  --exclude 'dist' \
  --exclude 'node_modules' \
  --exclude 'coverage.out' \
  --exclude 'demo/output' \
  "$ROOT/" "$TMP/src/"

cd "$TMP/src"

echo "== module and formatting =="
go mod verify
unformatted=$(gofmt -l cmd internal packs demo examples)
if [ -n "$unformatted" ]; then
  printf 'clean-room: gofmt required:\n%s\n' "$unformatted" >&2
  exit 1
fi

echo "== tests =="
go test -shuffle=on -race ./...

echo "== demo =="
./demo/run.sh
./demo/verify.sh

echo "== benchmark =="
./bench/run.sh

if [ "$WITH_SCREENSHOTS" -eq 1 ]; then
  echo "== screenshots =="
  ./demo/screenshots.sh
else
  echo "== screenshots =="
  echo "skipped (pass --with-screenshots to render the committed PNGs)"
fi

echo "clean-room: PASS"
