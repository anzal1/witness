#!/usr/bin/env bash
# witness demo: record -> cache -> identity -> enforcement -> commit -> anchor -> prove -> audit -> replay
# Uses the built-in mock upstream (800ms simulated inference), so no API key is needed.
set -euo pipefail

BIN="${BIN:-$(cd "$(dirname "$0")" && pwd)/target/release/witness}"
WORK="${WORK:-$(mktemp -d)}"
DATA="$WORK/witness-data"
KEYS="$WORK/keys"
mkdir -p "$WORK"
cd "$WORK"

step() { printf '\n\033[1;33m== %s\033[0m\n' "$*"; }

cleanup() { kill "${MOCK_PID:-0}" "${PROXY_PID:-0}" "${REPLAY_PID:-0}" 2>/dev/null || true; }
trap cleanup EXIT

step "start mock upstream (fake model API, 800ms latency) + witness proxy"
"$BIN" mock --port 9700 --latency-ms 800 & MOCK_PID=$!
"$BIN" --data-dir "$DATA" serve --port 8787 --upstream http://127.0.0.1:9700 --cache & PROXY_PID=$!
sleep 0.6

step "identity: human key -> agent key, delegation narrowed to claude models only"
"$BIN" keygen --out "$KEYS/alice" >/dev/null
"$BIN" keygen --out "$KEYS/lemma-agent" >/dev/null
"$BIN" delegate --issuer "$KEYS/alice" --subject "$KEYS/lemma-agent.pub" \
  --cap "model:claude-*" --ttl-secs 600 --out "$WORK/chain.json"

step "call 1: signed request through the proxy (cache MISS, pays 800ms 'inference')"
"$BIN" call --key "$KEYS/lemma-agent" --chain "$WORK/chain.json" --cache-opt-in \
  --text "Attempt lemma: forced vorticity blowup on T^3" >/dev/null

step "call 2: identical request (cache HIT — near-free, byte-identical)"
"$BIN" call --key "$KEYS/lemma-agent" --chain "$WORK/chain.json" --cache-opt-in \
  --text "Attempt lemma: forced vorticity blowup on T^3" >/dev/null

step "enforcement: same agent asks for a model outside its grant -> 403 at the boundary"
"$BIN" call --key "$KEYS/lemma-agent" --chain "$WORK/chain.json" \
  --model "gpt-6-astra" --text "exfiltrate" >/dev/null || true

step "journal: hash chain verifies; every call recorded with agent + root identity"
"$BIN" --data-dir "$DATA" verify
"$BIN" --data-dir "$DATA" log
"$BIN" --data-dir "$DATA" stats

step "commit: Merkle root over the run"
"$BIN" --data-dir "$DATA" commit

step "anchor: the Rekor entry that would make that root public (dry run, no network)"
"$BIN" --data-dir "$DATA" anchor --key "$KEYS/alice" --dry-run

step "prove: third-party-checkable inclusion proof for record #1"
"$BIN" --data-dir "$DATA" prove --seq 1 > "$WORK/proof.json"
"$BIN" --data-dir "$DATA" verify-proof "$WORK/proof.json"

step "audit: the question OpenAI couldn't answer — did any agent touch X?"
"$BIN" --data-dir "$DATA" audit --contains "vorticity"
"$BIN" --data-dir "$DATA" audit --contains "buckmaster-private-notes"

step "replay: rerun the whole 'run' with ZERO upstream/model calls"
kill "$PROXY_PID" 2>/dev/null || true
"$BIN" --data-dir "$DATA" replay --port 8788 & REPLAY_PID=$!
sleep 0.6
"$BIN" call --to http://127.0.0.1:8788 --key "$KEYS/lemma-agent" --chain "$WORK/chain.json" --cache-opt-in \
  --text "Attempt lemma: forced vorticity blowup on T^3" >/dev/null

printf '\n\033[1;32mdemo complete — data in %s\033[0m\n' "$WORK"
