#!/usr/bin/env bash
# Render the generated HTML cards into committed README screenshots.
set -u
set -o pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT" || exit 1

OUT="$ROOT/demo/output"
SHOTS="$ROOT/demo/screenshots"
PLAYWRIGHT_CHANNEL=${PLAYWRIGHT_CHANNEL:-chrome}
VIEWPORT=${VIEWPORT:-1280,900}

if ! command -v npx >/dev/null 2>&1; then
  echo "screenshots: npx is required (Node.js + Playwright CLI)" >&2
  exit 1
fi
if [ ! -f "$OUT/01-overview/card.html" ]; then
  echo "screenshots: run demo/run.sh first" >&2
  exit 1
fi
mkdir -p "$SHOTS"

file_url() {
  node -e 'process.stdout.write("file://" + encodeURI(process.argv[1]))' "$1"
}

capture() {
  local name=$1
  local path=$2
  local url
  url=$(file_url "$path")
  printf '  %-28s ' "$name"
  local args=(screenshot --viewport-size "$VIEWPORT" --full-page)
  if [ -n "$PLAYWRIGHT_CHANNEL" ]; then
    args+=(--channel "$PLAYWRIGHT_CHANNEL")
  fi
  if npx --no-install playwright "${args[@]}" "$url" "$SHOTS/$name.png" >/dev/null 2>"$OUT/$name.screenshot.log"; then
    printf 'ok\n'
  else
    printf 'FAILED\n'
    cat "$OUT/$name.screenshot.log" >&2
    return 1
  fi
}

failures=0
count=0
requested=("$@")

selected() {
  local name=$1
  if [ "${#requested[@]}" -eq 0 ]; then
    return 0
  fi
  local item
  for item in "${requested[@]}"; do
    if [ "$item" = "$name" ]; then
      return 0
    fi
  done
  return 1
}

for card in "$OUT"/*/card.html; do
  [ -f "$card" ] || continue
  name=$(basename "$(dirname "$card")")
  if ! selected "$name"; then
    continue
  fi
  count=$((count + 1))
  if [ "$name" = "17-report-html" ]; then
    if ! capture "$name" "$OUT/17-report-html/report.html"; then
      failures=$((failures + 1))
    fi
    continue
  fi
  if ! capture "$name" "$card"; then
    failures=$((failures + 1))
  fi
done

printf '\nRendered %d screenshots into %s (%d failures).\n' "$count" "$SHOTS" "$failures"
if [ "$failures" -ne 0 ]; then
  exit 1
fi
