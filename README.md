# witness

**A flight recorder for AI agent fleets that pays for itself.**

`witness` is a single-binary, API-compatible proxy that sits between your agents and a model API. Agents change one line — the base URL — and every call is:

- **recorded** — request and response stored in a content-addressed object store, referenced from a hash-chained journal (tamper-evident: any edit, deletion, or reorder breaks the chain);
- **attributed** — agents sign requests with Ed25519 keys and carry delegation chains from a human root key, verified locally at the proxy with zero network calls (the **Pact** protocol);
- **cached** — identical deterministic requests are served from the record instead of re-paying inference; a whole run can be **replayed** later with zero model calls (the **AgentReplay** protocol);
- **enforced** — delegations are narrowing-only capability grants (`model:claude-*`); a request outside the grant is refused *at the network boundary*, not by policy;
- **provable** — a Merkle commitment over the journal lets you hand a third party an inclusion proof for any record, or answer *"did any agent ever touch X?"* against a committed root.

That last question is the one OpenAI could not answer in September 2026, when it [could not rule out](https://venturebeat.com/technology/openai-solves-longstanding-math-problem-with-10-000-agent-swarm-but-cant-rule-out-benefitting-from-a-researchers-private-codex-data) that a researcher's private data had leaked into its 10,000-agent Navier–Stokes run. With witness in the path, that's `witness audit --contains <x>` — with a proof.

## Quickstart

```bash
cargo build --release
./demo.sh          # full lifecycle against a built-in mock upstream, no API key needed
```

Real usage:

```bash
# record + cache in front of Anthropic
witness serve --port 8787 --upstream https://api.anthropic.com --cache
# then point your agents at http://127.0.0.1:8787 instead of api.anthropic.com
```

## Identity (Pact)

```bash
witness keygen --out keys/alice                       # human root key
witness keygen --out keys/agent                       # agent key
witness delegate --issuer keys/alice --subject keys/agent.pub \
  --cap "model:claude-*" --ttl-secs 3600 --out chain.json
witness call --key keys/agent --chain chain.json --text "hello"   # signed request
```

Chains sub-delegate with `--parent chain.json`; capabilities can only narrow — escalation fails cryptographically. Run the proxy with `--mode required --trust keys/alice.pub` to refuse anything not anchored to a trusted human key.

Headers: `x-pact-identity` (hex pubkey), `x-pact-timestamp`, `x-pact-signature` (Ed25519 over `METHOD\nPATH\nTIMESTAMP\nblake3(body)`), `x-pact-delegation` (base64 JSON chain).

## Record, prove, audit (AgentReplay)

```bash
witness verify                     # journal hash chain intact?
witness commit                     # Merkle root over the run — anchor it anywhere public
witness prove --seq 42 > proof.json
witness verify-proof proof.json    # third-party checkable
witness audit --contains "secret-dataset-name"
witness replay --port 8788         # serve the recorded run; zero upstream calls; misses are 409
```

Every response carries `x-witness-seq`, `x-witness-req`, `x-witness-resp` (BLAKE3 hashes), and `x-witness-cache: miss|hit|replay`.

## Cache policy (honest by design)

LLM calls are nondeterministic. Everything is **recorded**, but a response is only **reused** when that's semantically sound: `temperature: 0`, an explicit `seed`, or the caller opting in with `x-witness-cache: allow`. Replay mode reuses everything — that's its point.

## What this does NOT do

- It cannot see influence through **model weights** — if data leaked into training, no request trace shows it.
- A prompt-injected agent holding a valid delegation is authorized-and-rogue; witness narrows the blast radius and gives perfect forensics, it does not prevent the injection.
- Commitments bind only if published externally (a transparency log, a timestamped post). An unpublished root proves nothing to anyone else.

## Design

Rust, ~2k lines: `tokio`/`axum` proxy, BLAKE3 hashing (incremental — streams are fingerprinted as they pass through), `ed25519-dalek`, flat-file git-style CAS, JSONL hash-chained journal, hand-rolled Merkle (~100 lines, fully tested). One static binary, no database, no daemon dependencies.

```
agent ──signed request──▶ witness ──▶ model API
                            │
                            ├─ objects/   content-addressed bodies
                            ├─ journal.log  hash-chained records
                            ├─ cache/     request-key → response index
                            └─ commitments/  Merkle roots
```

## Roadmap

- Fleet mode: shared cache across many witness instances (consistent hashing, gRPC)
- OpenAI-compatible upstream shapes (`/v1/chat/completions`) — the proxy is path-agnostic today, cache/audit already work
- Anchoring helper: publish commitment roots to a public transparency log (e.g. Rekor)
- Verifier oracles: mark records `verified-by` (test suite, Lean check) to unlock unconditional reuse
