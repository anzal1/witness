#!/usr/bin/env bash
# Measure witness's added latency. Requires oha (brew install oha).
#
# The mock upstream runs with --latency-ms 0 so proxy overhead is not hidden
# behind simulated inference. Four scenarios isolate each layer:
#
#   1. direct        oha -> mock                  (baseline: HTTP + mock cost)
#   2. record        oha -> witness -> mock       (CAS write + journal append)
#   3. record+sign   same, with Pact headers      (adds Ed25519 verification)
#   4. cache hit     oha -> witness (no upstream) (served from the record)
#
# Added overhead is scenario N minus scenario 1.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release/witness"
N="${N:-2000}"        # requests per scenario
C="${C:-20}"          # concurrent connections
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }
command -v oha >/dev/null || { echo "install oha: brew install oha" >&2; exit 1; }

WORK="$(mktemp -d)"
cleanup() { kill ${PIDS:-} 2>/dev/null || true; }
trap cleanup EXIT
PIDS=""
cd "$WORK"

BODY='{"model":"claude-sonnet-5","max_tokens":64,"temperature":0,"messages":[{"role":"user","content":"benchmark request"}]}'
printf '%s' "$BODY" > body.json

"$BIN" mock --port 9800 --latency-ms 0 >/dev/null 2>&1 &
PIDS="$PIDS $!"
"$BIN" --data-dir rec  serve --port 9801 --upstream http://127.0.0.1:9800 >/dev/null 2>&1 &
PIDS="$PIDS $!"
"$BIN" --data-dir hit  serve --port 9802 --upstream http://127.0.0.1:9800 --cache >/dev/null 2>&1 &
PIDS="$PIDS $!"
sleep 1

"$BIN" keygen --out human >/dev/null 2>&1
"$BIN" keygen --out agent >/dev/null 2>&1
"$BIN" delegate --issuer human --subject agent.pub --cap "model:claude-*" --ttl-secs 600 --out chain.json >/dev/null 2>&1
# One signature, reused for every request: valid inside the 5-minute skew window.
SIGN_ARGS=()
while IFS= read -r h; do
  [ -n "$h" ] && SIGN_ARGS+=(-H "$h")
done < <("$BIN" sign --key agent --chain chain.json --body-file body.json)

# Warm the cache scenario so every measured request is a hit.
curl -s -X POST -H 'content-type: application/json' -d "$BODY" http://127.0.0.1:9802/v1/messages >/dev/null

run() { # name, url, extra args...
  local name="$1" url="$2"; shift 2
  local out
  out=$(oha -n "$N" -c "$C" --no-tui -m POST \
        -H 'content-type: application/json' "$@" -d "$BODY" "$url" 2>&1)
  local p50 p99 rps
  # oha prints its own unit per line (secs/ms/us) - keep it.
  p50=$(awk '/50.00%/ {print $3" "$4}' <<<"$out" | head -1)
  p99=$(awk '/99.00%/ {print $3" "$4}' <<<"$out" | head -1)
  rps=$(awk '/Requests\/sec/ {print $2}' <<<"$out" | head -1)
  printf '%-14s p50=%-12s p99=%-12s req/s=%s\n' "$name" "$p50" "$p99" "$rps"
}

echo "witness bench — n=$N c=$C, mock latency 0ms, $(uname -sm)"
echo
run "direct"      http://127.0.0.1:9800/v1/messages
run "record"      http://127.0.0.1:9801/v1/messages
run "record+sign" http://127.0.0.1:9801/v1/messages "${SIGN_ARGS[@]}"
run "cache-hit"   http://127.0.0.1:9802/v1/messages
echo
echo "journal records written: rec=$("$BIN" --data-dir rec stats | awk '/^records/{print $2}')"
