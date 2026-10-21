#!/bin/sh
# Builds the admin UI fixture, serves it on loopback and runs the
# accessibility check against it. Needs Go (or FIXTURE_BIN), Node and
# Chrome; run `npm ci --ignore-scripts` in tools/a11y first.
set -eu

root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
pid=""
cleanup() {
  [ -n "$pid" ] && kill "$pid" 2>/dev/null && wait "$pid" 2>/dev/null
  rm -rf "$work"
}
trap cleanup EXIT INT TERM

fixture=${FIXTURE_BIN:-}
if [ -z "$fixture" ]; then
  fixture="$work/fixture"
  (cd "$root" && CGO_ENABLED=0 go build -trimpath -o "$fixture" ./tools/a11y/fixture)
fi
mkdir -m 700 "$work/data" "$work/tmp"
"$fixture" -dir "$work/data" -ready "$work/ready" -port "${A11Y_PORT:-0}" &
pid=$!
i=0
while [ ! -s "$work/ready" ]; do
  i=$((i + 1))
  if [ "$i" -gt 100 ] || ! kill -0 "$pid" 2>/dev/null; then
    echo "run.sh: fixture did not start" >&2
    exit 1
  fi
  sleep 0.1
done
TMPDIR="$work/tmp" node "$root/tools/a11y/check.mjs" "$(sed -n 1p "$work/ready")" "$(sed -n 2p "$work/ready")"
