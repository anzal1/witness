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
- **tool calls join the same chain:** `witness mcp -- <server>` wraps a stdio MCP server, so one journal covers what your agents asked a model *and* what they did with tools;
- **commands are recorded by what they changed:** `witness run -- <command>` fingerprints the working directory before and after, so the journal carries the side effects too and not only the instruction;
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

### Standard export (IETF agent-record draft)

The native journal format is witness's own. [draft-maintainer-1f916-agent-record-01](https://datatracker.ietf.org/doc/draft-maintainer-1f916-agent-record/) standardises very nearly the same object, so witness can also emit its record as a draft-shaped dossier:

```bash
witness export-record --out dossier/                    # whole journal
witness export-record --out dossier/ --agent <hex-pubkey> \
  --sign-key keys/registry                              # one agent, explicit signer
witness verify-record dossier/                          # offline, no network
witness verify-record dossier/ --registry-key <hex>     # with an out-of-band key pin
```

The export writes `dossier.json` (keys, events, inclusion proofs, checkpoint, registry signature), `checkpoint.json` (the signed tree head on its own, so a third party can countersign it), and `registry.pub`. Verification is fully offline and reports the draft's four-valued verdict.

**Conformance, honestly.** The draft is SHA-256 throughout where witness is natively BLAKE3, so this is a translation and not a rename: events are re-hashed under SHA-256 and re-committed under an RFC 6962 tree, and each exported event keeps the BLAKE3 hash of the journal record it came from so the two artifacts pin to each other.

What matches the draft exactly:

- key binding payload `1f916.key-bind.v1:<handle>:<pk_b64url>` and RFC 7638 thumbprints over the Ed25519 JWK (Section 3.1);
- checkpoint payload `1f916.checkpoint.v1:<log>:<tree_size>:<root_hex>:<created_at_ms>`, Ed25519-signed (Section 3.2);
- RFC 6962 Section 2.1 leaf and node hashing, and Section 2.1.1 inclusion proofs (Section 3.2);
- dossier signature `1f916.record.v1:<sha256_hex>` over the SHA-256 of the JCS-canonical core (Section 3.6);
- the anchor rule and the four-valued verdict, so a dossier verified with a key read out of its own file reports `unanchored`, never "verified" (Section 3.6);
- the Section 3.6 hardening rules: indices halved by integer division rather than bitwise shift, and hashes validated as exactly 64 lowercase hex characters before decoding.

What is **provisional**, because draft -01 does not specify it:

- the event object. Section 2 says only that an event "carries the hash of its predecessor" and gives no field names, types, or hash input. Our `Event` fields are our own choice and are flagged as such in `src/agent_record.rs`;
- the member list of the "dossier core", which Section 3.6 hashes but never enumerates, plus the on-disk file names and media type (Section 5 registers nothing);
- custody. Section 3.1 says registries MUST record a custody disclosure, but witness only ever sees a public key at the proxy boundary, so it emits `undisclosed`, a value outside the draft's taxonomy and deliberately not a claim.

What witness does **not** implement:

- witnesses (Section 3.3). There are no countersignatures, so the `witnessed` verdict is unreachable and `verify-record` never returns it;
- consistency proofs between two checkpointed sizes, and signed write receipts (Section 3.2);
- the unauthenticated registry HTTP surface (Section 3.2). A dossier is a file, not a service;
- memory seals (Section 3.4) and cross-agent attestations (Section 3.5), which witness has no source of;
- key rotation and revocation events (Section 3.1). Witness observes keys in traffic, it does not run their lifecycle, so a key binding it exports carries a signature only when the exporter also held that agent's secret key. Otherwise `binding_signature` is `null`, meaning observed rather than attested.

This is an early implementation of an individual submission that has no IETF standing yet. Treat the format as tracking a moving target.

## Recording tool calls (MCP)

The proxy above records the **model** boundary. `witness mcp` records the **tool** boundary, into the same journal and the same content-addressed store, so one `witness audit` answers "what did my agents actually do" across both.

It is a transparent stdio wrapper. You put it in front of any MCP server; it spawns that server, pipes JSON-RPC between the client and the server line by line, and writes a record for every `tools/call` and its matching response.

```bash
witness mcp -- npx -y @modelcontextprotocol/server-filesystem ~/projects
```

In a Claude Desktop or Claude Code style `mcpServers` config, change the command and push the real server behind `--`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "witness",
      "args": [
        "--data-dir", "/Users/you/witness-data",
        "mcp", "--agent", "claude-desktop", "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/Users/you/projects"
      ]
    }
  }
}
```

Nothing else changes. The client still talks to the server it configured, the server's stderr still goes where it always went, and on exit witness prints a one line summary of what it recorded and what it let pass.

Tool calls land in the journal as ordinary invoke records, so `verify`, `log`, `commit`, `prove` and `audit` work on them unchanged:

| field | value |
| --- | --- |
| `agent` | `mcp-client`, or whatever `--agent` says |
| `path` | `mcp:tools/call:<tool name>` |
| `upstream` | `mcp:<server program>` |
| `model` | absent, a tool call has no model |
| `cache` | `miss`, v1 records tool calls but never replays them |
| `status` | `200`, or `500` if the reply is a JSON-RPC error |
| `req` / `resp` | content hashes of the full request and response frames |

So after a session:

```bash
witness audit --contains "customers.csv"   # which agent read that file, through which tool
witness verify                             # one chain over model calls and tool calls together
```

### What v1 does not do

Stated plainly, because the gaps matter more than the feature list:

- **stdio transport only.** Streamable HTTP MCP servers are not wrapped. The stdio framing is newline delimited JSON-RPC 2.0 per the [MCP specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio) revision `2026-07-28`, which has been the same in every published revision, so older servers work too.
- **`tools/call` only.** `initialize`, `tools/list`, `resources/*`, `prompts/*` and every notification are forwarded untouched and merely counted. They are visible in the exit summary and nowhere else.
- **No replay and no cache at this boundary.** Tool calls have side effects. Serving one from a record would be a lie about what happened, so witness records them and stops there.
- **No identity yet.** MCP carries no Pact signature, so tool records are attributed to the `--agent` label rather than to a verified key. The label is operator asserted, not proven.
- **Correlation is by JSON-RPC id.** A server that never answers a call leaves it unrecorded, and the summary says how many.

## Recording command execution (Layer 3)

The proxy records the **model** boundary and `witness mcp` records the **tool** boundary. Both capture a conversation. `witness run` records the **execution** boundary, which is where a conversation turns into a changed file:

```bash
witness run -- pytest -x                       # snapshot cwd, run, snapshot again
witness run --dir ./service -- make build      # snapshot only this subtree
witness run --agent nightly-ci -- ./deploy.sh  # label the record
witness run --docker python:3.12 -- python etl.py
witness diff --seq 42                          # what did that run change?
```

It runs the command the way a shell would. Your terminal still gets stdout and stderr live, stdin is still inherited, and the exit code is propagated, so `witness run -- <anything>` is a drop-in prefix inside a Makefile, a CI step, or an agent's shell tool.

### What is recorded

Before the command runs, witness walks the working directory and computes a BLAKE3 hash for every file. It runs the command, tees both output streams, then walks the directory again. The record is the difference between those two walks.

One ordinary invoke record lands in the journal, so `verify`, `log`, `commit`, `prove` and `audit` work on it unchanged:

| field | value |
| --- | --- |
| `agent` | `exec`, or whatever `--agent` says |
| `path` | `exec:<command basename>` |
| `upstream` | `exec`, or `exec:docker:<image>` |
| `model` | absent, a command has no model |
| `cache` | `miss`, a command has side effects and is never replayed |
| `status` | `200` on exit 0, `500` on any other exit |
| `req` | CAS hash of the invocation manifest |
| `resp` | CAS hash of the result manifest |

The two manifests are JSON objects in the same content-addressed store as every model body and tool frame:

- **invocation:** `argv`, absolute `cwd`, `runtime` (`host` or `docker:<image>`), `started_ms`, and `pre_snapshot`, the hash of the before-walk.
- **result:** `exit_code`, `duration_ms`, `stdout` and `stderr` (hashes of the captured bytes, plus their lengths), `post_snapshot`, counts of added, modified and deleted paths, and `diff`, the explicit list of changes with old and new hash on each side.
- **snapshot:** the walk itself, a sorted map of relative path to `{hash, size}`. Sorted, so the manifest's own hash is stable and two runs over an unchanged tree produce one object.

`witness audit --contains <string>` follows an execution record one hop into its captured stdout and stderr, so "which run printed this" is answerable and not just "which run was asked to do this".

Directories that are noise or that would loop are never walked: `.git`, `target`, `node_modules`, and witness's own `witness-data`. Dotfiles are skipped too unless you pass `--include-hidden`, which reaches dotfiles but still never reaches those four. A tree over 50,000 files is refused with a message telling you to narrow `--dir`, and any file over 64 MB is hashed by streaming rather than being read into memory.

### Trust model, stated plainly

**This observes effects. It does not prevent them.** A snapshot diff is a description of what changed in one directory, produced by the same machine that ran the command. Nothing here stops a command from doing anything.

`--docker <image>` bind-mounts the working directory at `/work` and runs the command inside the image (`docker run --rm -v <dir>:/work -w /work <image> <cmd...>`). That adds real containment: the command reaches the mounted directory and whatever the image gives it, and not the rest of your filesystem. But containment is not proof. The record still says what witness observed on the host side of the mount, not what the container was prevented from doing, and it inherits whatever you think of the image, the daemon, and the kernel underneath. If Docker is not running, `--docker` fails immediately with a clear message rather than quietly falling back to the host.

Treat `witness run` as a flight recorder for commands, not as a sandbox. If you need a sandbox, run one, and point witness at it.

### Honest limits

- **Writes outside `--dir` are invisible.** A command that edits `/etc`, your home directory, or a sibling checkout produces an empty diff. The record's scope is exactly one subtree.
- **Network side effects are invisible.** A command that POSTs your database to a stranger and changes no file looks identical to `true`. Route model and tool traffic through `witness serve` and `witness mcp` if you want that leg recorded.
- **Only file content is diffed.** Permission and ownership changes, mtimes, empty directories created or removed, and extended attributes leave no trace.
- **Symlinks are skipped.** Following them would let a snapshot wander outside `--dir` and could cycle, so links are neither followed nor recorded, and a command that only changes a link's target shows nothing.
- **The diff is a before-and-after, not a history.** A file written, deleted, and rewritten byte-identically inside one command is correctly reported as unchanged, because it is. Intermediate states are not observed.
- **Concurrent writers confuse it.** If something else edits the directory while the command runs, that edit is attributed to the command. The boundary is temporal, not causal.
- **No identity yet.** Like MCP, a command carries no Pact signature, so the record is attributed to the `--agent` label. That label is operator asserted, not proven.
- **Skipped by default means skipped in evidence.** If your command's real output lands in `target/` or `node_modules/`, narrow `--dir` to it, because the default skip list will hide it.

## Cache policy (honest by design)

LLM calls are nondeterministic. Everything is **recorded**, but a response is only **reused** when that's semantically sound: `temperature: 0`, an explicit `seed`, or the caller opting in with `x-witness-cache: allow`. Replay mode reuses everything — that's its point.

### Verifier oracles

There is a fourth way to earn reuse, and it does not look at the sampling parameters at all. If something outside witness has checked the answer and found it good, the answer is good. A verified result does not care what temperature produced it.

`witness attest` runs a command of your choosing over a recorded response body and treats its exit status as the verdict:

```bash
# seq 1 was a temperature 1.0 call: recorded, never reused
witness attest --seq 1 --oracle 'pytest -q' --name pytest
witness attest --seq 1 --oracle 'lake env lean Proof.lean' --name lean
witness attest --seq 1 --oracle 'jq -e .content[0].text' --name schema

witness attested          # seq, name, req_key for every attested request
```

The response body arrives on the command's stdin. Exit 0 verifies, anything else refutes. A refuted attestation writes nothing at all: no marker, no journal record, and the command's own exit status comes back out of `witness attest` so a script can branch on it. A verified one does two things. It appends a record to the same hash chain, whose `path` is `attest:<name>:<target seq>`, whose `req` is the attested record's chain hash, and whose `resp` resolves in the CAS to the exact command, exit status and stdout that vouched for it. And it writes a marker under `<data-dir>/attested/<request key>`, which the proxy stats before its sampling checks. From then on that one request is served from the record regardless of its temperature.

Scope is one request, not one prompt and not one model. The marker is keyed by the cache key of the exact request that was attested: method, path, and canonical request body. Change a single token of the prompt and you are back to a miss, because you are asking a different question and nothing has verified the answer to it.

**The trust model, stated plainly.** An oracle attestation is worth exactly as much as the oracle command. `--oracle true` will happily attest anything, and witness will not stop you. What witness does instead is refuse to let that be invisible: the command string, the target record, the exit status and the output all go into the journal, under the same Merkle commitments and the same Rekor anchor as everything else. An auditor does not have to take "verified" on faith. They can read which command vouched for which response, and decide for themselves whether that command was worth believing. The signature from `--key` says who ran the oracle, not that the oracle was any good.

One operational note: `witness attest` appends through its own handle while a proxy may be serving. A handle re-reads the chain tip when the file has grown beneath it, so attesting a live journal is safe. The journal still expects one hot writer per data directory; two proxies on one data dir was never supported and still is not.

## Fleet mode v1 (peer cache)

Many witness instances, one warm cache. On a local miss, an instance asks its siblings for that exact request key before it pays the upstream. This is squid sibling behaviour: no central node, no consistent hashing, no cluster membership, no service discovery. Each instance is told who its peers are, and asks them in order.

```bash
# instance A: an ordinary recording proxy whose cache siblings may read
witness serve --cache --peer-token "$FLEET_TOKEN"

# instance B: the same, plus two siblings to ask before the upstream
witness serve --cache --peer-token "$FLEET_TOKEN" \
  --peer http://10.0.1.11:8787 \
  --peer http://10.0.1.12:8787
```

`--peer` is repeatable and the order you give is the order they are asked. `--peer-token` is one shared secret used in both directions: required on inbound peer reads, sent on outbound ones. Serving the route and asking peers are independent, so an instance with no `--peer` still answers its siblings.

**The protocol is one route.** `GET /witness/peer/cache/<request key>` returns the stored response body with its original `content-type`, plus `x-witness-status` (the status the upstream actually gave) and `x-witness-resp` (the BLAKE3 hash of the body). A key that is not cached is a plain `404`. Like `/witness/metrics` it is a route rather than a branch inside the proxy handler, so a peer read is never forwarded upstream and never journaled as a model call.

**A peer hit is adopted, not proxied.** The bytes go into the local CAS, the local cache index gets the entry, and the call is journaled locally with `cache: "peer"` and `upstream: "peer:<host:port>"`. The response carries `x-witness-cache: peer`. The next identical request on that instance is an ordinary local hit that touches no one.

**Token model.** The token authenticates the reader and nothing else; content addressing does the rest. A peer's body must hash to the `x-witness-resp` it advertised or the answer is dropped and counted as an error, so a compromised sibling can withhold and can observe which keys you ask for, but it cannot feed a neighbour bytes of its choosing. Without `--peer-token` the route is open to anything that can reach the port, which is only sane on a network you already trust. The token is a secret in a flag, not an identity: it does not say which sibling asked, it is not Pact, and it does not appear in any journal record.

**A dead peer costs 300ms, at most, per lookup.** Each peer gets a 300ms budget covering connect, response and body read. Over budget, unreachable, unauthorized and hash mismatch all count into `witness_peer_errors_total`, and the lookup moves to the next peer and then to the upstream. Peers are consulted only where a local hit would have been allowed anyway: `--cache` on, the request reusable under the policy above, and not replay mode. Replay ignores the fleet completely, because zero network is the whole point of replay.

### What fleet mode v1 does not do

Stated plainly, because this is a v1 and the gaps are the interesting part:

- **No consistent hashing and no sharding.** Every instance asks every peer it was given. That is fine for a handful of siblings and wrong for fifty.
- **No dedupe of concurrent identical misses.** Two instances that miss on the same request at the same moment both call the upstream. A peer cache shortens the second wave, not the first.
- **Journals stay per-instance.** Each instance is its own witness with its own hash chain, and adopting a sibling's bytes does not adopt its record. A fleet-wide audit means verifying and reading N journals. It is also why the record says `peer:<host:port>`: a call inherited from a sibling never claims to have reached the model.
- **No membership, health checking or backoff.** A peer that is down is retried on every miss and costs its budget every time.
- **Pull only.** Instances never push entries to each other, so a cold instance warms only through the traffic it actually serves.
- **Oracle attestations do not travel.** An instance reads its own `attested/` markers when it decides whether a request is reusable, so a sibling's verdict does not come along with the sibling's bytes. Attest on each instance that should honour it, or keep a shared data directory out of scope for now.
- **No compression and no streaming on the peer read.** A recorded SSE response crosses the wire as one body, exactly as a local cache hit replays it.

This partially addresses issue #1; consistent hashing, single-flight across instances and a transport other than plain HTTP are still open.
## Observability

Two optional projections of the same record. The journal stays the source of truth; both of these exist so witness can feed the monitoring stack you already run.

**Prometheus.** The proxy exposes its own counters at `GET /witness/metrics` in text exposition format, hand-written, with no client library and no added dependency. That path is a route rather than a branch inside the proxy handler, so it is never forwarded upstream and never journaled.

```
witness_requests_total{cache="hit|miss|peer|replay"}  counter
witness_requests_signed_total                     counter    requests with a verified Pact signature
witness_journal_records                           gauge      current journal length
witness_upstream_errors_total                     counter    transport failures, unreadable bodies, truncated streams
witness_peer_hits_total                           counter    requests answered from a sibling instance's cache
witness_peer_errors_total                         counter    peer lookups that failed rather than cleanly missed
witness_otlp_spans_exported_total                 counter
witness_otlp_spans_dropped_total                  counter    backpressure or a failed export
witness_request_duration_seconds                  histogram  15 buckets, 0.0005s to 30s
```

The counters are process-local and reset when the proxy restarts. `witness_journal_records` is the durable one: it reads the journal's sequence number, so it carries across restarts.

**OpenTelemetry.** `--otlp-endpoint` also projects every recorded call onto a GenAI span.

```bash
witness serve --cache --otlp-endpoint http://127.0.0.1:4318
```

Spans go out as OTLP/HTTP with a JSON body. A base URL gets `/v1/traces` appended; a full traces URL is used as given. Each span is named `chat <model>` and carries the GenAI semantic convention attributes `gen_ai.system`, `gen_ai.request.model` and `gen_ai.operation.name`, plus `witness.seq`, `witness.cache`, `witness.req_hash`, `witness.resp_hash` and `witness.agent`, which tie the span back to the journal record and to the exact bytes in the CAS.

Honest scope: this projection is minimal by design. The JSON is built by hand, none of the `opentelemetry` crates are pulled in, and a single background task drains a bounded channel. There is no context propagation, no sampling and no retry, so every span is its own root trace, and under backpressure spans are dropped and counted rather than allowed to slow the request path. If you want a real tracing pipeline, instrument your agent framework; use this to get witness's cache and provenance data onto a dashboard you already have.

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

| **[Armalo](https://www.armalo.ai/learn/merkle-tree-agent-audit-logs)** | Merkle audit logs **anchored to Sigstore Rekor** with inclusion proofs | Already ships the external anchoring that is only issue #2 here |
| **[IETF draft-maintainer-1f916-agent-record](https://datatracker.ietf.org/doc/draft-maintainer-1f916-agent-record/)** | Ed25519-bound append-only logs, signed Merkle heads, independent countersigning witnesses | It is becoming a **standard**, and it has a live registry with independent witnesses. Witness now exports to it (`witness export-record`, see [Standard export](#standard-export-ietf-agent-record-draft)) but runs no witnesses of its own |
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


Rust: `tokio`/`axum` proxy, BLAKE3 hashing (incremental, so streams are fingerprinted as they pass through), `ed25519-dalek`, flat-file git-style CAS, JSONL hash-chained journal, hand-rolled Merkle (fully tested). SHA-256 appears only where an external format demands it: Rekor entries and the RFC 6962 tree in the standard export. One static binary, no database, no daemon dependencies.

```
agent ──signed request──▶ witness ──▶ model API
                            │
                            ├─ objects/   content-addressed bodies
                            ├─ journal.log  hash-chained records
                            ├─ cache/     request-key → response index
                            ├─ attested/  request keys an oracle vouched for
                            └─ commitments/  Merkle roots + Rekor anchor receipts

Rust, ~2.5k lines: `tokio`/`axum` proxy, a line-streamed stdio MCP wrapper, BLAKE3 hashing (incremental — streams are fingerprinted as they pass through), `ed25519-dalek`, flat-file git-style CAS, JSONL hash-chained journal, hand-rolled Merkle (~100 lines, fully tested). One static binary, no database, no daemon dependencies.

```
agent ─────signed request────▶ witness serve ──▶ model API     (model boundary)
MCP client ──stdio JSON-RPC──▶ witness mcp   ──▶ MCP server    (tool boundary)
shell ───────────argv─────────▶ witness run   ──▶ command       (execution boundary)
                                    │
                                    ├─ objects/     content-addressed bodies
                                    ├─ journal.log  one hash chain over both
                                    ├─ cache/       request-key → response index
                                    ├─ attested/    request keys an oracle vouched for
                                    └─ commitments/ Merkle roots
```

## Roadmap

- MCP beyond v1: Streamable HTTP transport, recording `resources/*` and `prompts/*`, and Pact identity carried in `_meta` so tool calls are attributed to a key rather than a label
- Fleet mode beyond v1: consistent hashing so a large fleet does not ask everyone everything, single-flight so concurrent identical misses cost one upstream call, peer health tracking, and a transport that is not one HTTP GET per lookup
- OpenAI-compatible upstream shapes (`/v1/chat/completions`) — the proxy is path-agnostic today, cache/audit already work
- Oracle policy: attest a *class* of requests (a prompt template, a model, an agent) rather than one exact request, without giving up the audit trail that makes a single attestation legible
