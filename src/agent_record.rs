//! Standard export: the journal rendered as an Agent Record dossier, per
//! draft-maintainer-1f916-agent-record-01 ("The Agent Record: Transparent,
//! Witness-Countersigned Event Logs for AI Agent Identity, History, and
//! Memory").
//!
//! The native witness record is BLAKE3-chained and committed with a BLAKE3
//! Merkle tree (see `journal` and `merkle`). The draft is SHA-256 throughout:
//! RFC 6962 leaf and node hashing (Section 3.2), RFC 7638 key thumbprints
//! (Section 3.1), RFC 8785 canonical JSON (Sections 3.5 and 3.6). So this
//! module is a translation layer, not a rename: events are re-hashed under
//! SHA-256 and re-committed under an RFC 6962 tree, with each event carrying
//! the BLAKE3 hash of the native journal record it came from, so a holder of
//! both artifacts can pin one to the other.
//!
//! What the draft specifies and this module follows exactly:
//!   - Section 3.1 key binding payload `1f916.key-bind.v1:<handle>:<pk_b64url>`
//!     and RFC 7638 thumbprints over the Ed25519 JWK.
//!   - Section 3.2 checkpoint payload
//!     `1f916.checkpoint.v1:<log>:<tree_size>:<root_hex>:<created_at_ms>`,
//!     with RFC 6962 Section 2.1 leaf/node hashing and Section 2.1.1
//!     inclusion proofs.
//!   - Section 3.6 dossier signature `1f916.record.v1:<sha256_hex>` over the
//!     JCS-canonical dossier core, the anchor rule, and the four-valued
//!     verdict.
//!
//! What the draft leaves open, and is therefore marked PROVISIONAL below:
//!   - The event object itself. Section 2 says only that an event "carries
//!     the hash of its predecessor"; no field names, types, or hash input are
//!     given anywhere in -01. Every field of `Event` is our choice.
//!   - The member list of the "dossier core" (Section 3.6 names the term and
//!     hashes it, but never enumerates it) and the on-disk file names.

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::identity::{parse_pubkey, Keypair};
use crate::journal::{now_ms, Record};

/// The draft revision this module was written against.
pub const SPEC: &str = "draft-maintainer-1f916-agent-record-01";
pub const SPEC_URL: &str = "https://datatracker.ietf.org/doc/draft-maintainer-1f916-agent-record/";

const PREFIX_KEY_BIND: &str = "1f916.key-bind.v1";
const PREFIX_CHECKPOINT: &str = "1f916.checkpoint.v1";
const PREFIX_RECORD: &str = "1f916.record.v1";

const ZERO_SHA256: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Dossier file names. PROVISIONAL: Section 3.6 describes a dossier's
/// contents but names no files and registers no media type (Section 5 has no
/// IANA actions at all).
pub const FILE_DOSSIER: &str = "dossier.json";
pub const FILE_CHECKPOINT: &str = "checkpoint.json";
pub const FILE_REGISTRY_KEY: &str = "registry.pub";

// ---------------------------------------------------------------- encoding --

fn b64url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// RFC 8785 canonical JSON, over the subset of JSON this module emits.
///
/// serde_json's object is a `BTreeMap<String, _>`, so re-serializing sorts
/// keys by UTF-8 byte order and writes compact separators; for ASCII keys
/// that is byte-for-byte what JCS requires. Rather than assume the input
/// stays in that subset, this rejects what would diverge: non-ASCII member
/// names (UTF-16 code unit ordering differs above the BMP) and any
/// non-integer number (JCS mandates ECMAScript number formatting, which
/// serde_json does not implement).
pub fn jcs(value: &Value) -> Result<Vec<u8>> {
    check_jcs_subset(value, "$")?;
    Ok(serde_json::to_vec(value)?)
}

fn check_jcs_subset(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Number(n) => {
            if n.as_u64().is_none() && n.as_i64().is_none() {
                bail!("{path}: non-integer numbers are outside this JCS subset");
            }
            Ok(())
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                check_jcs_subset(item, &format!("{path}[{i}]"))?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (key, item) in map {
                if !key.is_ascii() {
                    bail!("{path}: member name {key:?} is not ASCII");
                }
                check_jcs_subset(item, &format!("{path}.{key}"))?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Decode a hash the way Section 3.6 requires: "exactly 64 lowercase
/// hexadecimal characters before decoding".
pub fn parse_sha256_hex(label: &str, text: &str) -> Result<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        bail!("{label}: expected 64 lowercase hex characters, got {text:?}");
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out).with_context(|| format!("{label}: not hex"))?;
    Ok(out)
}

// ------------------------------------------------------------- RFC 6962 ----

/// Merkle tree hashing exactly as in Section 2.1 of RFC 6962, which
/// Section 3.2 of the draft adopts by reference.
pub mod rfc6962 {
    use super::sha256;

    pub fn leaf_hash(entry: &[u8; 32]) -> [u8; 32] {
        sha256(&[&[0x00], entry.as_slice()])
    }

    pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
        sha256(&[&[0x01], left.as_slice(), right.as_slice()])
    }

    /// Largest power of two strictly less than `n` (`n > 1`). Integer
    /// arithmetic only: Section 3.6 of the draft warns that shift operators
    /// which coerce to 32 bits let a 2^32+1 tree size forge proofs.
    fn split_point(n: usize) -> usize {
        let mut k = 1usize;
        while k * 2 < n {
            k *= 2;
        }
        k
    }

    /// MTH(D[n]) over already-hashed entries.
    pub fn tree_head(entries: &[[u8; 32]]) -> [u8; 32] {
        match entries.len() {
            0 => sha256(&[]),
            1 => leaf_hash(&entries[0]),
            n => {
                let k = split_point(n);
                node_hash(&tree_head(&entries[..k]), &tree_head(&entries[k..]))
            }
        }
    }

    /// PATH(m, D[n]) per Section 2.1.1 of RFC 6962.
    pub fn audit_path(index: usize, entries: &[[u8; 32]]) -> Option<Vec<[u8; 32]>> {
        if index >= entries.len() {
            return None;
        }
        if entries.len() == 1 {
            return Some(Vec::new());
        }
        let k = split_point(entries.len());
        let mut path = if index < k {
            audit_path(index, &entries[..k])?
        } else {
            audit_path(index - k, &entries[k..])?
        };
        if index < k {
            path.push(tree_head(&entries[k..]));
        } else {
            path.push(tree_head(&entries[..k]));
        }
        Some(path)
    }

    /// Inclusion proof verification per Section 2.1.3.2 of RFC 9162. Indices
    /// are halved with integer division, never shifted, for the reason given
    /// in `split_point`.
    pub fn verify_inclusion(
        leaf_index: u64,
        tree_size: u64,
        leaf: &[u8; 32],
        path: &[[u8; 32]],
        root: &[u8; 32],
    ) -> bool {
        if tree_size == 0 || leaf_index >= tree_size {
            return false;
        }
        let mut fnode = leaf_index;
        let mut snode = tree_size - 1;
        let mut running = *leaf;
        for sibling in path {
            if snode == 0 {
                return false;
            }
            if !fnode.is_multiple_of(2) || fnode == snode {
                running = node_hash(sibling, &running);
                while fnode != 0 && fnode.is_multiple_of(2) {
                    fnode /= 2;
                    snode /= 2;
                }
            } else {
                running = node_hash(&running, sibling);
            }
            fnode /= 2;
            snode /= 2;
        }
        snode == 0 && running == *root
    }
}

// ------------------------------------------------------------------ model --

/// One entry of an agent's log.
///
/// PROVISIONAL, all of it. Draft -01 Section 2 defines an event as "an
/// append-only log entry. Each event carries the hash of its predecessor" and
/// nothing further: no field names, no types, no statement of what the hash
/// is taken over. The shape below is witness's choice, chosen to mirror the
/// native `journal::Record` so the two stay diffable. `event_hash` is
/// SHA-256 over the JCS-canonical form of this object with the `event_hash`
/// member removed; because `predecessor` is itself a member, that single hash
/// binds the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    /// 1-based position in the exported log. PROVISIONAL (no draft field).
    pub seq: u64,
    /// `event_hash` of the preceding event, or 64 zeros for the first.
    pub predecessor: String,
    /// `key-bind` (Section 3.1) or `invoke` (witness extension: the draft's
    /// named event kinds are key lifecycle, seal, and attestation only).
    pub event_type: String,
    pub recorded_at_ms: u64,
    /// Draft Section 3.1 calls this the `<handle>`; witness uses the agent's
    /// hex Ed25519 public key, or the literal `anonymous`.
    pub agent: String,
    pub payload: Value,
    pub event_hash: String,
}

impl Event {
    fn compute_hash(&self) -> Result<String> {
        let mut value = serde_json::to_value(self)?;
        value
            .as_object_mut()
            .expect("event serializes to an object")
            .remove("event_hash");
        Ok(hex::encode(sha256(&[&jcs(&value)?])))
    }
}

/// A key bound to the log per Section 3.1.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundKey {
    /// Unpadded base64url of the raw 32-byte Ed25519 public key.
    pub public_key: String,
    /// RFC 7638 thumbprint over `{"crv":"Ed25519","kty":"OKP","x":...}`.
    pub thumbprint: String,
    /// Section 3.1: "Registries MUST record a custody disclosure for each
    /// key, drawn from an extensible taxonomy (self_held, platform_held,
    /// household_held, threshold(k,n), kms, hsm, session_delegated)."
    /// witness never learns custody (agents present only a public key at the
    /// proxy boundary), so it emits `undisclosed`, which is outside the
    /// draft's taxonomy and is a deliberate declaration of ignorance rather
    /// than a claim.
    pub custody: String,
    pub bound_at_ms: u64,
    /// The exact UTF-8 string a binding signature covers.
    pub binding_payload: String,
    /// Hex Ed25519 signature over `binding_payload`, present only when the
    /// exporter held that agent's private key. Null otherwise: a key seen in
    /// traffic is recorded, not attested.
    pub binding_signature: Option<String>,
}

/// A signed Merkle tree head, Section 3.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub log: String,
    pub tree_size: u64,
    pub root_sha256: String,
    pub created_at_ms: u64,
    /// The exact payload signed, reproduced so a reader need not reconstruct
    /// the colon-delimited form to see what was covered.
    pub signed_payload: String,
    pub signature: String,
    /// Hex public key of the signer. Per the anchor rule (Section 3.6) a key
    /// read from here proves internal consistency only.
    pub registry_key: String,
}

/// Section 3.6 signs "the SHA-256 of the JCS-canonical dossier core" but
/// never enumerates the core. PROVISIONAL: witness takes the core to be
/// everything below, which is every claim the dossier makes apart from the
/// registry signature itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DossierCore {
    pub spec: String,
    pub spec_url: String,
    pub producer: String,
    pub log: String,
    pub subject: String,
    pub keys: Vec<BoundKey>,
    pub events: Vec<Event>,
    pub inclusion_proofs: Vec<InclusionProof>,
    pub checkpoint: Checkpoint,
    /// Section 3.4. witness records no memory seals.
    pub seals: Vec<Value>,
    /// Section 3.5. witness issues no cross-agent attestations.
    pub attestations: Vec<Value>,
    /// Section 3.3. witness is not a registry with independent witnesses, so
    /// a dossier it produces never carries one.
    pub witness_countersignatures: Vec<Value>,
    /// Non-normative provenance back to the native artifact.
    pub source: Value,
}

/// RFC 6962 Section 2.1.1 inclusion proof for one event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub audit_path: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySignature {
    pub core_sha256: String,
    pub signed_payload: String,
    pub signature: String,
    pub registry_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dossier {
    pub core: DossierCore,
    pub registry_signature: RegistrySignature,
}

// ----------------------------------------------------------------- export --

pub struct ExportOptions<'a> {
    pub records: &'a [Record],
    /// Restrict to one agent handle (hex public key, or `anonymous`).
    pub agent: Option<&'a str>,
    /// Key playing the registry role: it signs the checkpoint and the
    /// dossier.
    pub signer: &'a Keypair,
    pub out_dir: &'a Path,
}

#[derive(Debug)]
pub struct ExportSummary {
    pub log: String,
    pub events: usize,
    pub tree_size: u64,
    pub root_sha256: String,
    pub files: Vec<PathBuf>,
}

/// Log identifier. Must not contain `:` because Section 3.2's checkpoint
/// payload is colon-delimited and the draft gives no escaping rule (it takes
/// the same care with seal labels in Section 3.4).
fn log_id(agent: Option<&str>) -> String {
    match agent {
        Some(handle) => format!("witness-{handle}"),
        None => "witness-journal".to_string(),
    }
}

fn binding_payload(handle: &str, public_key_b64url: &str) -> String {
    format!("{PREFIX_KEY_BIND}:{handle}:{public_key_b64url}")
}

fn checkpoint_payload(log: &str, tree_size: u64, root_hex: &str, created_at_ms: u64) -> String {
    format!("{PREFIX_CHECKPOINT}:{log}:{tree_size}:{root_hex}:{created_at_ms}")
}

fn record_payload(core_sha256: &str) -> String {
    format!("{PREFIX_RECORD}:{core_sha256}")
}

/// RFC 7638 thumbprint of an Ed25519 public key, as Section 3.1 specifies.
pub fn jwk_thumbprint(public_key: &[u8; 32]) -> Result<String> {
    let jwk = json!({"crv": "Ed25519", "kty": "OKP", "x": b64url(public_key)});
    Ok(b64url(&sha256(&[&jcs(&jwk)?])))
}

fn key_bind_event(handle: &str, bound_at_ms: u64, signer: &Keypair) -> Result<(BoundKey, Value)> {
    let key =
        parse_pubkey(handle).with_context(|| format!("agent handle {handle} is not a key"))?;
    let raw = key.to_bytes();
    let public_key = b64url(&raw);
    let payload = binding_payload(handle, &public_key);
    // A binding signature is only producible when we hold the agent's secret
    // key. Signing with the registry key instead would be a forgery dressed
    // as conformance.
    let binding_signature = if signer.public_hex() == handle {
        Some(hex::encode(
            signer.signing.sign(payload.as_bytes()).to_bytes(),
        ))
    } else {
        None
    };
    let bound = BoundKey {
        public_key,
        thumbprint: jwk_thumbprint(&raw)?,
        custody: "undisclosed".to_string(),
        bound_at_ms,
        binding_payload: payload,
        binding_signature,
    };
    let event_payload = serde_json::to_value(&bound)?;
    Ok((bound, event_payload))
}

fn invoke_payload(record: &Record) -> Value {
    json!({
        "path": record.path,
        "model": record.model,
        "upstream": record.upstream,
        "cache": record.cache,
        "status": record.status,
        "request_blake3": record.req,
        "response_blake3": record.resp,
        "delegation_root": record.root,
        "request_signature": record.sig,
        "journal_seq": record.seq,
        "journal_blake3": record.hash,
    })
}

/// Convert journal records into a dossier and write it to `out_dir`.
pub fn export(opts: ExportOptions<'_>) -> Result<ExportSummary> {
    let selected: Vec<&Record> = match opts.agent {
        Some(handle) => opts.records.iter().filter(|r| r.agent == handle).collect(),
        None => opts.records.iter().collect(),
    };
    if selected.is_empty() {
        match opts.agent {
            Some(handle) => bail!("no journal records for agent {handle}"),
            None => bail!("journal is empty; nothing to export"),
        }
    }

    let log = log_id(opts.agent);
    if log.contains(':') {
        bail!(
            "log identifier {log} contains ':', which the checkpoint payload uses as a separator"
        );
    }

    // Section 3.1: key lifecycle events MUST be recorded as log events, so
    // every key the export mentions gets a key-bind event ahead of its use.
    let mut first_seen: BTreeMap<&str, u64> = BTreeMap::new();
    for record in &selected {
        first_seen.entry(&record.agent).or_insert(record.ts_ms);
    }

    let mut keys = Vec::new();
    let mut events: Vec<Event> = Vec::new();
    let mut previous = ZERO_SHA256.to_string();
    let mut seq = 1u64;

    for (handle, ts_ms) in &first_seen {
        if *handle == "anonymous" {
            continue;
        }
        let (bound, payload) = key_bind_event(handle, *ts_ms, opts.signer)?;
        keys.push(bound);
        let mut event = Event {
            seq,
            predecessor: previous.clone(),
            event_type: "key-bind".to_string(),
            recorded_at_ms: *ts_ms,
            agent: (*handle).to_string(),
            payload,
            event_hash: String::new(),
        };
        event.event_hash = event.compute_hash()?;
        previous = event.event_hash.clone();
        seq += 1;
        events.push(event);
    }

    for record in &selected {
        let mut event = Event {
            seq,
            predecessor: previous.clone(),
            event_type: "invoke".to_string(),
            recorded_at_ms: record.ts_ms,
            agent: record.agent.clone(),
            payload: invoke_payload(record),
            event_hash: String::new(),
        };
        event.event_hash = event.compute_hash()?;
        previous = event.event_hash.clone();
        seq += 1;
        events.push(event);
    }

    let entries: Vec<[u8; 32]> = events
        .iter()
        .map(|e| parse_sha256_hex("event hash", &e.event_hash))
        .collect::<Result<_>>()?;
    let root = rfc6962::tree_head(&entries);
    let root_hex = hex::encode(root);
    let tree_size = entries.len() as u64;

    let inclusion_proofs = (0..entries.len())
        .map(|i| {
            let path = rfc6962::audit_path(i, &entries).context("building inclusion proof")?;
            Ok(InclusionProof {
                leaf_index: i as u64,
                tree_size,
                audit_path: path.iter().map(hex::encode).collect(),
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let created_at_ms = now_ms();
    let payload = checkpoint_payload(&log, tree_size, &root_hex, created_at_ms);
    let checkpoint = Checkpoint {
        log: log.clone(),
        tree_size,
        root_sha256: root_hex.clone(),
        created_at_ms,
        signature: hex::encode(opts.signer.signing.sign(payload.as_bytes()).to_bytes()),
        signed_payload: payload,
        registry_key: opts.signer.public_hex(),
    };

    let core = DossierCore {
        spec: SPEC.to_string(),
        spec_url: SPEC_URL.to_string(),
        producer: concat!("witness/", env!("CARGO_PKG_VERSION")).to_string(),
        log: log.clone(),
        subject: opts.agent.unwrap_or("*").to_string(),
        keys,
        events,
        inclusion_proofs,
        checkpoint: checkpoint.clone(),
        seals: Vec::new(),
        attestations: Vec::new(),
        witness_countersignatures: Vec::new(),
        source: json!({
            "format": "witness journal.log",
            "chain_hash": "blake3",
            "first_seq": selected.first().unwrap().seq,
            "last_seq": selected.last().unwrap().seq,
        }),
    };

    let core_value = serde_json::to_value(&core)?;
    let core_sha256 = hex::encode(sha256(&[&jcs(&core_value)?]));
    let signed_payload = record_payload(&core_sha256);
    let registry_signature = RegistrySignature {
        core_sha256,
        signature: hex::encode(
            opts.signer
                .signing
                .sign(signed_payload.as_bytes())
                .to_bytes(),
        ),
        signed_payload,
        registry_key: opts.signer.public_hex(),
    };

    let events_written = core.events.len();
    let dossier = Dossier {
        core,
        registry_signature,
    };

    std::fs::create_dir_all(opts.out_dir)
        .with_context(|| format!("creating {}", opts.out_dir.display()))?;
    let dossier_path = opts.out_dir.join(FILE_DOSSIER);
    let checkpoint_path = opts.out_dir.join(FILE_CHECKPOINT);
    let key_path = opts.out_dir.join(FILE_REGISTRY_KEY);
    std::fs::write(&dossier_path, serde_json::to_vec_pretty(&dossier)?)?;
    std::fs::write(&checkpoint_path, serde_json::to_vec_pretty(&checkpoint)?)?;
    std::fs::write(&key_path, opts.signer.public_hex())?;

    Ok(ExportSummary {
        log,
        events: events_written,
        tree_size,
        root_sha256: root_hex,
        files: vec![dossier_path, checkpoint_path, key_path],
    })
}

// ----------------------------------------------------------- verification --

/// The four-valued verdict of Section 3.6. Ordering here is strongest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// All proofs verify and a caller-pinned independent witness countersigns
    /// the checkpoint, asserting continuity from a previously observed head.
    /// witness is not a registry with independent witnesses (Section 3.3), so
    /// a dossier it produces can never reach this verdict, and this verifier
    /// never returns it.
    Witnessed,
    /// All proofs verify against a caller-supplied registry key, with no
    /// pinned witness countersignature. Section 3.6: this "MUST NOT be
    /// reported as fully verified".
    ConsistentUnwitnessed,
    /// All proofs verify, but every key came from the artifact under test.
    /// Internal consistency only, no claim of authenticity.
    Unanchored,
    /// Any proof fails, or a key does not match a caller-supplied pin.
    /// Returned as an `Err` by `verify`, never as a report.
    Diverged,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Witnessed => "witnessed",
            Verdict::ConsistentUnwitnessed => "consistent-unwitnessed",
            Verdict::Unanchored => "unanchored",
            Verdict::Diverged => "diverged",
        }
    }
}

#[derive(Debug)]
pub struct VerifyReport {
    pub verdict: Verdict,
    pub log: String,
    pub subject: String,
    pub events: usize,
    pub tree_size: u64,
    pub root_sha256: String,
    pub registry_key: String,
    pub unsigned_bindings: usize,
}

/// Offline-verify a dossier directory. `pinned_registry_key` is a hex public
/// key that reached the verifier outside the dossier; without it the best
/// available verdict is `unanchored`.
pub fn verify(dir: &Path, pinned_registry_key: Option<&str>) -> Result<VerifyReport> {
    let dossier_path = dir.join(FILE_DOSSIER);
    let raw = std::fs::read(&dossier_path)
        .with_context(|| format!("reading {}", dossier_path.display()))?;
    // Hash the core exactly as it sits on disk, not as it round-trips through
    // our own structs, so an added or renamed member still breaks the seal.
    let raw_value: Value =
        serde_json::from_slice(&raw).with_context(|| format!("{FILE_DOSSIER} is not JSON"))?;
    let core_value = raw_value
        .get("core")
        .context("dossier has no `core` member")?
        .clone();
    let dossier: Dossier = serde_json::from_value(raw_value)
        .with_context(|| format!("{FILE_DOSSIER} is not an agent-record dossier"))?;
    let core = &dossier.core;

    if core.spec != SPEC {
        bail!(
            "dossier declares spec {:?}, this verifier implements {SPEC}",
            core.spec
        );
    }
    if core.events.is_empty() {
        bail!("dossier contains no events");
    }

    // 1. Event hashes and the predecessor chain.
    let mut previous = ZERO_SHA256.to_string();
    for (i, event) in core.events.iter().enumerate() {
        if event.predecessor != previous {
            bail!(
                "event {} (seq {}): predecessor mismatch, chain break (declared {}, expected {})",
                i,
                event.seq,
                event.predecessor,
                previous
            );
        }
        let computed = event.compute_hash()?;
        if computed != event.event_hash {
            bail!(
                "event {} (seq {}): event hash mismatch, content was altered (declared {}, computed {})",
                i,
                event.seq,
                event.event_hash,
                computed
            );
        }
        previous = event.event_hash.clone();
    }

    // 2. Merkle tree head over the event hashes.
    let entries: Vec<[u8; 32]> = core
        .events
        .iter()
        .map(|e| parse_sha256_hex("event hash", &e.event_hash))
        .collect::<Result<_>>()?;
    if core.checkpoint.tree_size != entries.len() as u64 {
        bail!(
            "checkpoint tree_size {} does not match the {} events in the dossier",
            core.checkpoint.tree_size,
            entries.len()
        );
    }
    let root = rfc6962::tree_head(&entries);
    let declared_root = parse_sha256_hex("checkpoint root", &core.checkpoint.root_sha256)?;
    if root != declared_root {
        bail!(
            "tree head mismatch: checkpoint claims {}, the events yield {}",
            core.checkpoint.root_sha256,
            hex::encode(root)
        );
    }

    // 3. Inclusion proofs.
    if core.inclusion_proofs.len() != core.events.len() {
        bail!(
            "dossier has {} events but {} inclusion proofs",
            core.events.len(),
            core.inclusion_proofs.len()
        );
    }
    for (i, proof) in core.inclusion_proofs.iter().enumerate() {
        if proof.tree_size != core.checkpoint.tree_size {
            bail!(
                "inclusion proof {i}: tree_size {} does not match the checkpoint's {}",
                proof.tree_size,
                core.checkpoint.tree_size
            );
        }
        if proof.leaf_index != i as u64 {
            bail!(
                "inclusion proof {i}: leaf_index {} is out of order",
                proof.leaf_index
            );
        }
        let path = proof
            .audit_path
            .iter()
            .map(|h| parse_sha256_hex("audit path node", h))
            .collect::<Result<Vec<_>>>()?;
        let leaf = rfc6962::leaf_hash(&entries[i]);
        if !rfc6962::verify_inclusion(proof.leaf_index, proof.tree_size, &leaf, &path, &root) {
            bail!(
                "inclusion proof {i} (event seq {}) does not verify against the checkpoint root",
                core.events[i].seq
            );
        }
    }

    // 4. Checkpoint signature.
    let expected_payload = checkpoint_payload(
        &core.checkpoint.log,
        core.checkpoint.tree_size,
        &core.checkpoint.root_sha256,
        core.checkpoint.created_at_ms,
    );
    if expected_payload != core.checkpoint.signed_payload {
        bail!(
            "checkpoint signed_payload does not match its own fields (declared {:?}, expected {:?})",
            core.checkpoint.signed_payload,
            expected_payload
        );
    }
    if core.checkpoint.log != core.log {
        bail!(
            "checkpoint names log {:?}, dossier names {:?}",
            core.checkpoint.log,
            core.log
        );
    }
    verify_sig(
        &core.checkpoint.registry_key,
        &core.checkpoint.signature,
        expected_payload.as_bytes(),
        "checkpoint signature",
    )?;

    // 5. Registry signature over the JCS-canonical core.
    let core_sha256 = hex::encode(sha256(&[&jcs(&core_value)?]));
    if core_sha256 != dossier.registry_signature.core_sha256 {
        bail!(
            "dossier core digest mismatch: signature covers {}, the core hashes to {}",
            dossier.registry_signature.core_sha256,
            core_sha256
        );
    }
    let expected_record_payload = record_payload(&core_sha256);
    if expected_record_payload != dossier.registry_signature.signed_payload {
        bail!("registry signed_payload is not {expected_record_payload:?}");
    }
    verify_sig(
        &dossier.registry_signature.registry_key,
        &dossier.registry_signature.signature,
        expected_record_payload.as_bytes(),
        "registry signature",
    )?;
    if dossier.registry_signature.registry_key != core.checkpoint.registry_key {
        bail!("the checkpoint and the dossier were signed by different keys");
    }

    // 6. Key bindings, where they carry a signature.
    let mut unsigned_bindings = 0usize;
    for key in &core.keys {
        let raw = URL_SAFE_NO_PAD
            .decode(&key.public_key)
            .context("bound key is not unpadded base64url")?;
        let raw: [u8; 32] = raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("bound key is not 32 bytes"))?;
        if key.thumbprint != jwk_thumbprint(&raw)? {
            bail!("bound key {}: RFC 7638 thumbprint mismatch", key.public_key);
        }
        let handle = hex::encode(raw);
        if key.binding_payload != binding_payload(&handle, &key.public_key) {
            bail!("bound key {}: binding payload is malformed", key.public_key);
        }
        match &key.binding_signature {
            Some(sig) => verify_sig(&handle, sig, key.binding_payload.as_bytes(), "key binding")?,
            None => unsigned_bindings += 1,
        }
    }

    // 7. Sidecar files must agree with the dossier.
    let sidecar = dir.join(FILE_CHECKPOINT);
    if sidecar.exists() {
        let on_disk: Checkpoint = serde_json::from_slice(&std::fs::read(&sidecar)?)
            .with_context(|| format!("{FILE_CHECKPOINT} is not a checkpoint"))?;
        if on_disk.signed_payload != core.checkpoint.signed_payload
            || on_disk.signature != core.checkpoint.signature
        {
            bail!("{FILE_CHECKPOINT} disagrees with the checkpoint inside {FILE_DOSSIER}");
        }
    }
    let key_file = dir.join(FILE_REGISTRY_KEY);
    if key_file.exists() {
        let on_disk = std::fs::read_to_string(&key_file)?;
        if on_disk.trim() != core.checkpoint.registry_key {
            bail!("{FILE_REGISTRY_KEY} disagrees with the key named in the dossier");
        }
    }

    // 8. The anchor rule, Section 3.6.
    let verdict = match pinned_registry_key {
        Some(pin) => {
            if pin.trim() != core.checkpoint.registry_key {
                bail!(
                    "pinned registry key {} does not match the dossier's {}",
                    pin.trim(),
                    core.checkpoint.registry_key
                );
            }
            Verdict::ConsistentUnwitnessed
        }
        None => Verdict::Unanchored,
    };

    Ok(VerifyReport {
        verdict,
        log: core.log.clone(),
        subject: core.subject.clone(),
        events: core.events.len(),
        tree_size: core.checkpoint.tree_size,
        root_sha256: core.checkpoint.root_sha256.clone(),
        registry_key: core.checkpoint.registry_key.clone(),
        unsigned_bindings,
    })
}

fn verify_sig(key_hex: &str, sig_hex: &str, message: &[u8], label: &str) -> Result<()> {
    let key = parse_pubkey(key_hex).with_context(|| format!("{label}: public key"))?;
    let bytes: [u8; 64] = hex::decode(sig_hex)
        .with_context(|| format!("{label}: not hex"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label}: must be 64 bytes"))?;
    key.verify(message, &Signature::from_bytes(&bytes))
        .with_context(|| format!("{label} does not verify"))
}

/// Convenience for tests and callers that want to poke at one event on disk.
pub fn read_dossier(dir: &Path) -> Result<Map<String, Value>> {
    let raw = std::fs::read(dir.join(FILE_DOSSIER))?;
    let value: Value = serde_json::from_slice(&raw)?;
    match value {
        Value::Object(map) => Ok(map),
        _ => bail!("{FILE_DOSSIER} is not a JSON object"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{InvokeEntry, Journal};

    fn tmp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("witness-record-{tag}-{}", std::process::id()))
    }

    fn entry(agent: &str, n: u8) -> InvokeEntry {
        InvokeEntry {
            agent: agent.to_string(),
            root: None,
            req: format!("{:064x}", n),
            resp: format!("{:064x}", n as u32 + 1000),
            path: "/v1/messages".into(),
            model: Some("claude-sonnet-5".into()),
            upstream: "mock".into(),
            cache: "miss".into(),
            status: 200,
            sig: None,
        }
    }

    /// Build a synthetic journal and export it. Returns (dossier dir, signer).
    fn synthetic(tag: &str, agents: &[&str]) -> (PathBuf, PathBuf, Keypair) {
        let base = tmp_dir(tag);
        std::fs::remove_dir_all(&base).ok();
        let data = base.join("data");
        let journal = Journal::open(&data).unwrap();
        for (i, agent) in agents.iter().enumerate() {
            journal.append_invoke(entry(agent, i as u8 + 1)).unwrap();
        }
        let records = journal.read_all().unwrap();
        let signer = Keypair::generate().unwrap();
        let out = base.join("dossier");
        export(ExportOptions {
            records: &records,
            agent: None,
            signer: &signer,
            out_dir: &out,
        })
        .unwrap();
        (base, out, signer)
    }

    #[test]
    fn rfc6962_matches_known_vectors() {
        // RFC 6962 Section 2.1: MTH of the empty tree is SHA-256 of nothing.
        assert_eq!(
            hex::encode(rfc6962::tree_head(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        // A single entry is its leaf hash.
        let entry = [7u8; 32];
        assert_eq!(
            rfc6962::tree_head(&[entry]),
            rfc6962::leaf_hash(&entry),
            "single-entry tree head is the leaf hash"
        );
        // Two entries hash as one internal node.
        let other = [9u8; 32];
        assert_eq!(
            rfc6962::tree_head(&[entry, other]),
            rfc6962::node_hash(&rfc6962::leaf_hash(&entry), &rfc6962::leaf_hash(&other))
        );
    }

    #[test]
    fn inclusion_proofs_verify_for_every_index_and_size() {
        for n in 1..=17usize {
            let entries: Vec<[u8; 32]> = (0..n).map(|i| sha256(&[&[i as u8]])).collect();
            let root = rfc6962::tree_head(&entries);
            for i in 0..n {
                let path = rfc6962::audit_path(i, &entries).unwrap();
                let leaf = rfc6962::leaf_hash(&entries[i]);
                assert!(
                    rfc6962::verify_inclusion(i as u64, n as u64, &leaf, &path, &root),
                    "n={n} i={i}"
                );
                // A forged leaf must not verify against the same path.
                let forged = rfc6962::leaf_hash(&sha256(&[b"forged"]));
                assert!(
                    !rfc6962::verify_inclusion(i as u64, n as u64, &forged, &path, &root),
                    "forged leaf accepted at n={n} i={i}"
                );
            }
        }
    }

    #[test]
    fn thumbprint_is_base64url_of_a_sha256() {
        let key = Keypair::generate().unwrap();
        let raw = key.signing.verifying_key().to_bytes();
        let thumbprint = jwk_thumbprint(&raw).unwrap();
        assert_eq!(URL_SAFE_NO_PAD.decode(&thumbprint).unwrap().len(), 32);
        assert!(!thumbprint.contains('='));
    }

    #[test]
    fn jcs_rejects_what_it_cannot_canonicalize() {
        assert!(jcs(&json!({"a": 1, "b": "x"})).is_ok());
        assert!(jcs(&json!({"a": 1.5})).is_err());
        assert!(jcs(&json!({"café": 1})).is_err());
    }

    #[test]
    fn jcs_sorts_members_regardless_of_input_order() {
        let a = jcs(&json!({"b": 1, "a": 2})).unwrap();
        let b = jcs(&json!({"a": 2, "b": 1})).unwrap();
        assert_eq!(a, b);
        assert_eq!(String::from_utf8(a).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn round_trip_export_then_verify() {
        let alice = Keypair::generate().unwrap().public_hex();
        let (base, out, signer) = synthetic("roundtrip", &[&alice, &alice, "anonymous"]);

        let report = verify(&out, None).unwrap();
        // Three invokes plus one key-bind for alice; anonymous binds no key.
        assert_eq!(report.events, 4);
        assert_eq!(report.tree_size, 4);
        assert_eq!(report.verdict, Verdict::Unanchored);
        assert_eq!(report.unsigned_bindings, 1);

        // Pinning the signer's key out of band upgrades the verdict.
        let pinned = verify(&out, Some(&signer.public_hex())).unwrap();
        assert_eq!(pinned.verdict, Verdict::ConsistentUnwitnessed);

        // A wrong pin is divergence, not a weaker pass.
        let other = Keypair::generate().unwrap().public_hex();
        let err = verify(&out, Some(&other)).unwrap_err().to_string();
        assert!(err.contains("pinned registry key"), "{err}");

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn filtering_to_one_agent_exports_only_that_agent() {
        let alice = Keypair::generate().unwrap().public_hex();
        let bob = Keypair::generate().unwrap().public_hex();
        let base = tmp_dir("filter");
        std::fs::remove_dir_all(&base).ok();
        let data = base.join("data");
        let journal = Journal::open(&data).unwrap();
        journal.append_invoke(entry(&alice, 1)).unwrap();
        journal.append_invoke(entry(&bob, 2)).unwrap();
        journal.append_invoke(entry(&alice, 3)).unwrap();
        let records = journal.read_all().unwrap();
        let signer = Keypair::generate().unwrap();
        let out = base.join("dossier");
        let summary = export(ExportOptions {
            records: &records,
            agent: Some(&alice),
            signer: &signer,
            out_dir: &out,
        })
        .unwrap();
        // One key-bind plus two invokes.
        assert_eq!(summary.events, 3);
        let report = verify(&out, None).unwrap();
        assert_eq!(report.subject, alice);
        assert!(report.log.ends_with(&alice));
        assert_eq!(report.unsigned_bindings, 1);

        assert!(export(ExportOptions {
            records: &records,
            agent: Some("nobody"),
            signer: &signer,
            out_dir: &out,
        })
        .is_err());

        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn self_export_carries_a_real_binding_signature() {
        let signer = Keypair::generate().unwrap();
        let handle = signer.public_hex();
        let base = tmp_dir("selfbind");
        std::fs::remove_dir_all(&base).ok();
        let journal = Journal::open(&base.join("data")).unwrap();
        journal.append_invoke(entry(&handle, 1)).unwrap();
        let records = journal.read_all().unwrap();
        let out = base.join("dossier");
        export(ExportOptions {
            records: &records,
            agent: None,
            signer: &signer,
            out_dir: &out,
        })
        .unwrap();
        let report = verify(&out, None).unwrap();
        assert_eq!(report.unsigned_bindings, 0);
        std::fs::remove_dir_all(&base).ok();
    }

    /// Rewrite one member of one event on disk and re-verify.
    fn tamper(dir: &Path, mutate: impl FnOnce(&mut Value)) {
        let mut map = read_dossier(dir).unwrap();
        let core = map.get_mut("core").unwrap();
        mutate(core);
        std::fs::write(
            dir.join(FILE_DOSSIER),
            serde_json::to_vec_pretty(&Value::Object(map)).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn tampering_with_an_event_fails_verification_precisely() {
        let alice = Keypair::generate().unwrap().public_hex();
        let (base, out, _signer) = synthetic("tamper-event", &[&alice, &alice]);
        assert!(verify(&out, None).is_ok());

        // Change the model recorded in the second event's payload.
        tamper(&out, |core| {
            core["events"][2]["payload"]["model"] = json!("gpt-6-astra");
        });

        let err = verify(&out, None).unwrap_err().to_string();
        assert!(
            err.contains("event 2") && err.contains("event hash mismatch"),
            "expected a precise per-event error, got: {err}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn recomputing_an_event_hash_still_breaks_the_chain() {
        let alice = Keypair::generate().unwrap().public_hex();
        let (base, out, _signer) = synthetic("tamper-rehash", &[&alice, &alice]);

        // A smarter forger edits the event and fixes its own hash. The next
        // event's predecessor no longer matches.
        let mut map = read_dossier(&out).unwrap();
        {
            let core = map.get_mut("core").unwrap();
            core["events"][1]["payload"]["status"] = json!(500);
            let mut event: Event = serde_json::from_value(core["events"][1].clone()).unwrap();
            event.event_hash = event.compute_hash().unwrap();
            core["events"][1] = serde_json::to_value(&event).unwrap();
        }
        std::fs::write(
            out.join(FILE_DOSSIER),
            serde_json::to_vec_pretty(&Value::Object(map)).unwrap(),
        )
        .unwrap();

        let err = verify(&out, None).unwrap_err().to_string();
        assert!(
            err.contains("event 2") && err.contains("predecessor mismatch"),
            "expected a chain break, got: {err}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn tampering_with_the_root_fails_before_the_signature_check() {
        let alice = Keypair::generate().unwrap().public_hex();
        let (base, out, _signer) = synthetic("tamper-root", &[&alice]);
        tamper(&out, |core| {
            core["checkpoint"]["root_sha256"] = json!(ZERO_SHA256);
        });
        let err = verify(&out, None).unwrap_err().to_string();
        assert!(err.contains("tree head mismatch"), "{err}");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn adding_an_unknown_member_breaks_the_core_digest() {
        let alice = Keypair::generate().unwrap().public_hex();
        let (base, out, _signer) = synthetic("tamper-extra", &[&alice]);
        tamper(&out, |core| {
            core["operator_note"] = json!("nothing to see here");
        });
        let err = verify(&out, None).unwrap_err().to_string();
        assert!(err.contains("core digest mismatch"), "{err}");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn swapping_the_registry_key_fails_the_signature() {
        let alice = Keypair::generate().unwrap().public_hex();
        let (base, out, _signer) = synthetic("tamper-key", &[&alice]);
        let impostor = Keypair::generate().unwrap().public_hex();
        tamper(&out, |core| {
            core["checkpoint"]["registry_key"] = json!(impostor);
        });
        // The checkpoint signature is checked before the core digest, so that
        // is the failure the verifier reports first.
        let err = format!("{:#}", verify(&out, None).unwrap_err());
        assert!(
            err.contains("checkpoint signature does not verify"),
            "{err}"
        );
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn tampering_with_the_sidecar_checkpoint_is_caught() {
        let alice = Keypair::generate().unwrap().public_hex();
        let (base, out, _signer) = synthetic("tamper-sidecar", &[&alice]);
        let mut checkpoint: Checkpoint =
            serde_json::from_slice(&std::fs::read(out.join(FILE_CHECKPOINT)).unwrap()).unwrap();
        checkpoint.signature = hex::encode([0u8; 64]);
        std::fs::write(
            out.join(FILE_CHECKPOINT),
            serde_json::to_vec_pretty(&checkpoint).unwrap(),
        )
        .unwrap();
        let err = verify(&out, None).unwrap_err().to_string();
        assert!(err.contains(FILE_CHECKPOINT), "{err}");
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn hash_strings_must_be_lowercase_hex_of_the_right_length() {
        assert!(parse_sha256_hex("x", ZERO_SHA256).is_ok());
        assert!(parse_sha256_hex("x", &ZERO_SHA256[1..]).is_err());
        assert!(parse_sha256_hex("x", &"A".repeat(64)).is_err());
        assert!(parse_sha256_hex("x", &"g".repeat(64)).is_err());
    }
}
