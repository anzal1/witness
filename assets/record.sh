#!/usr/bin/env bash
# Regenerate assets/demo.gif. Requires vhs (brew install vhs).
# Starts a mock upstream + witness proxy in a temp workdir, prepares Pact
# keys, then records assets/demo.tape against them.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$REPO/target/release/witness"
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 1; }

WORK="$(mktemp -d)"
cleanup() { kill "${MOCK_PID:-0}" "${PROXY_PID:-0}" 2>/dev/null || true; }
trap cleanup EXIT

cd "$WORK"
export PATH="$(dirname "$BIN"):$PATH"

witness mock --port 9700 --latency-ms 800 >/dev/null 2>&1 & MOCK_PID=$!
witness serve --port 8787 --upstream http://127.0.0.1:9700 --cache >/dev/null 2>&1 & PROXY_PID=$!
sleep 0.6

witness keygen --out keys/human >/dev/null 2>&1
witness keygen --out keys/agent >/dev/null 2>&1
witness delegate --issuer keys/human --subject keys/agent.pub \
  --cap "model:claude-*" --ttl-secs 3600 --out chain.json >/dev/null 2>&1

mkdir -p assets
vhs "$REPO/assets/demo.tape"
mv assets/demo.gif "$REPO/assets/demo.gif"
echo "wrote $REPO/assets/demo.gif"
