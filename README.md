# witness

**A recording cache for model APIs. You install it to cut inference spend and make crashed runs resumable — the byproduct is a record you can prove things about.**

[![ci](https://github.com/anzal1/witness/actions/workflows/ci.yml/badge.svg)](https://github.com/anzal1/witness/actions/workflows/ci.yml)
[![release](https://img.shields.io/github/v/release/anzal1/witness)](https://github.com/anzal1/witness/releases)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

![witness demo: 803ms cache miss, 541µs hit, 403 capability denial, Merkle commit, audit with agent attribution](assets/demo.gif)

`witness` is a single-binary, API-compatible proxy between your agents and a model API. Agents change one line — the base URL. Then:

- **repeat calls stop costing money** — every request and response is stored by content hash, so an identical deterministic call is served from the record instead of re-paying inference;
- **crashed runs resume instead of restarting** — a whole run can be **replayed** from the record with zero model calls (the **AgentReplay** protocol);
- **the record is tamper-evident** — entries live in a hash-chained journal, so any edit, deletion, or reorder breaks the chain and `witness verify` finds it;
- **calls are attributed** — agents sign requests with Ed25519 keys carrying delegation chains from a human root key, verified locally with zero network calls (the **Pact** protocol);
- **grants are enforced, not just logged** — delegations are narrowing-only (`model:claude-*`), and a request outside the grant is refused at the network boundary before it reaches the provider;
- **single records are provable to outsiders** — a Merkle commitment lets you hand a third party an inclusion proof, or answer *"did any agent ever touch X?"* against a committed root.

The ordering is the whole design bet. Audit tooling that asks to be adopted on principle doesn't get adopted, and a recorder switched on *after* a question is asked is worthless. So the thing you install for cost is the thing that turns out to be evidence — already running before anyone needed it.

This is a crowded, fast-moving space and several projects overlap heavily with this one. See [Prior art](#prior-art--read-this-before-you-adopt-it) before adopting — if you need a production agent gateway today, [Wirken](https://github.com/gebruder/wirken) is probably the better starting point.

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

Adoption is one changed line in your existing code — see [examples/](examples/) for the Anthropic SDK (Python/TS), LangGraph, and a fully signed shell flow.

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
witness commit                     # Merkle root over the run
witness anchor --key keys/alice    # publish that root to Sigstore Rekor
witness anchor-verify              # the log still says what the local file says
witness prove --seq 42 > proof.json
witness verify-proof proof.json    # third-party checkable
witness audit --contains "secret-dataset-name"
witness replay --port 8788         # serve the recorded run; zero upstream calls; misses are 409
```

Every response carries `x-witness-seq`, `x-witness-req`, `x-witness-resp` (BLAKE3 hashes), and `x-witness-cache: miss|hit|replay`.

### Anchoring to Rekor

A commitment sitting on your own disk is a claim about your own disk. Anchoring turns it into something a stranger can check:

```bash
witness anchor --key keys/alice                 # signs + publishes the latest commitment
witness anchor --key keys/alice --dry-run       # print the exact entry, post nothing
witness anchor-verify                           # re-fetch it and compare against the local file
```

`witness anchor` builds a Sigstore [`hashedrekord`](https://rekor.sigstore.dev) entry over the commitment file: its SHA-256, an Ed25519 signature by your key, and that key in SPKI/PEM form. It POSTs the entry to `https://rekor.sigstore.dev`, then writes the returned UUID and log index to `<commitment>.anchor.json`. Rekor is a public append-only log with its own signed timestamps, so the entry fixes the root in time: you cannot mint a root later and claim you held it earlier.

The log never sees your journal, your prompts, or your responses. It sees one 32-byte digest and one signature.

Anyone can check the entry without installing witness:

```bash
rekor-cli get --uuid <uuid> --rekor_server https://rekor.sigstore.dev
# or open https://search.sigstore.dev/?uuid=<uuid>
```

Use `--commitment <path>` to anchor an older commitment, and `--rekor-url` to target a private or self-hosted log.

## Cache policy (honest by design)

LLM calls are nondeterministic. Everything is **recorded**, but a response is only **reused** when that's semantically sound: `temperature: 0`, an explicit `seed`, or the caller opting in with `x-witness-cache: allow`. Replay mode reuses everything — that's its point.

## Overhead (measured, not claimed)

`bench/bench.sh` (needs [oha](https://github.com/hatoo/oha)) runs the mock upstream at `--latency-ms 0` so witness's own cost isn't hidden behind simulated inference. Four scenarios isolate each layer; numbers below are the median of 3 runs at n=2000, c=20 on an M-series MacBook:

| scenario | p50 | p99 | req/s | added p50 |
| --- | --- | --- | --- | --- |
| `direct` (baseline, straight to upstream) | 0.29 ms | 0.48 ms | 63k | — |
| `record` (CAS write + journal append) | 0.54 ms | 1.2 ms | 34k | **+0.25 ms** |
| `record+sign` (adds Ed25519 + chain verify) | 0.56 ms | 1.2 ms | 33k | **+0.27 ms** |
| `cache-hit` (served from the record) | 0.44 ms | 1.4 ms | 43k | +0.15 ms |

Reading these honestly:

- **Recording costs about a quarter of a millisecond** at the median. Against a model call that takes 2–30 *seconds*, that is roughly 0.01% overhead.
- **Signed identity is nearly free** — the delta between `record` and `record+sign` is ~20 µs, which is Ed25519 verification doing what Ed25519 does.
- **p99 shows occasional multi-millisecond outliers** (filesystem scheduling on the journal append). Sub-millisecond median, low-single-digit-millisecond tail — not a hard sub-ms p99 guarantee.
- **A cache hit's real saving isn't the 0.44 ms** — it's the entire upstream inference call that never happens.

Throughput plateaus around **37k recorded calls/sec** on this machine, and past that ceiling latency grows with concurrency (queueing, as expected):

| concurrency | p50 | p99 | req/s |
| --- | --- | --- | --- |
| 20 | 0.52 ms | 1.4 ms | 35k |
| 50 | 1.25 ms | 3.0 ms | 38k |
| 100 | 2.46 ms | 8.4 ms | 37k |
| 200 | 4.73 ms | 13.3 ms | 37k |

The limiter is the journal's serialized append — see [#9](https://github.com/anzal1/witness/issues/9) for the batched group-commit fix. For scale context: OpenAI's 10,000-agent run averaged ~8.5 messages/sec, about 4,000× below this ceiling. The model API will be your bottleneck, not witness.

## Prior art — read this before you adopt it

This is a crowded space, and several projects overlap heavily with witness. Some are more mature. An honest map:

| Project | Overlap with witness | Where it is ahead |
| --- | --- | --- |
| **[Wirken](https://github.com/gebruder/wirken)** (Rust, MIT) | Very high — per-agent Ed25519 identity signing a hash-chain head, SHA-256 chain, offline `sessions verify`, reproducible replay, capability-attenuated sub-agent delegation | Credential vault, per-channel process isolation, sandboxed exec, SIEM forwarding, OTel GenAI semconv. Bigger, older, actively developed |
| **[Bifrost](https://docs.getbifrost.ai/overview)** (commercial) | HMAC-signed audit events at creation, append-only archival | ~11µs gateway overhead vs witness's ~250µs |
| **[LiteLLM](https://github.com/BerriAI/litellm/discussions/25237)** (PRs #25329 / #30238) | Per-call post-quantum (ML-DSA-65) signature chaining, offline verification | Lives inside the most widely deployed LLM proxy |
| **[Armalo](https://www.armalo.ai/learn/merkle-tree-agent-audit-logs)** | Merkle audit logs **anchored to Sigstore Rekor** with inclusion proofs | Purpose-built audit product with a hosted UI; witness now anchors to Rekor too (`witness anchor`) |
| **[IETF draft-maintainer-1f916-agent-record](https://datatracker.ietf.org/doc/draft-maintainer-1f916-agent-record/)** | Ed25519-bound append-only logs, signed Merkle heads, independent countersigning witnesses | It is becoming a **standard**; witness currently implements a bespoke format |
| LiteLLM / Helicone / Portkey (base features) | Proxying, caching, logging | Mature, hosted, multi-provider |
| Dapr 1.18 attestation, OTel GenAI semconv | Workflow-history signing; trace schema | Established ecosystems |

**So what is actually different here?** Narrower than the feature list suggests:

1. **The cache is the point, the record is the byproduct.** Other tools sell audit as audit. Witness is built so the thing you install for cost and crash-resumption *is* the evidence store — so it is already running before anyone asks a question. Nobody else makes that the primary bet.
2. **Publicly verifiable rather than self-asserted.** Bifrost's HMAC means only the secret-holder can check a record; Ed25519 means anyone can. (Wirken and the IETF draft also use Ed25519.)
3. **Capabilities narrowed by signature, not by config.** Wirken's sub-agent ceilings are operator-configured policy; here a child grant that widens its parent's cannot be produced at all.
4. **One-line adoption.** Witness is a `base_url` change in front of any existing stack, not a runtime to migrate onto.

If you need a production agent gateway today, look at Wirken first. If you want a drop-in recording cache whose records happen to be independently verifiable, that is what this is.

## What this does NOT do

- It cannot see influence through **model weights** — if data leaked into training, no request trace shows it.
- A prompt-injected agent holding a valid delegation is authorized-and-rogue; witness narrows the blast radius and gives perfect forensics, it does not prevent the injection.
- Commitments bind only once published externally. `witness anchor` does that for you, but an *unanchored* root still proves nothing to anyone else, and anchoring inherits whatever trust you place in the Rekor instance you publish to.

## Design

Rust, ~2k lines: `tokio`/`axum` proxy, BLAKE3 hashing (incremental, so streams are fingerprinted as they pass through), `ed25519-dalek` (plus SHA-256, but only where Rekor's entry format demands it), flat-file git-style CAS, JSONL hash-chained journal, hand-rolled Merkle (~100 lines, fully tested). One static binary, no database, no daemon dependencies.

```
agent ──signed request──▶ witness ──▶ model API
                            │
                            ├─ objects/   content-addressed bodies
                            ├─ journal.log  hash-chained records
                            ├─ cache/     request-key → response index
                            └─ commitments/  Merkle roots + Rekor anchor receipts
```

## Roadmap

- Fleet mode: shared cache across many witness instances (consistent hashing, gRPC)
- OpenAI-compatible upstream shapes (`/v1/chat/completions`) — the proxy is path-agnostic today, cache/audit already work
- Verifier oracles: mark records `verified-by` (test suite, Lean check) to unlock unconditional reuse
